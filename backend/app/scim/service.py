import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User, UserRole
from app.auth.service import create_audit_log
from app.scim.models import ScimBearerToken

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


def _map_user_to_scim(user: User, base_url: str) -> dict:
    location = f"{base_url}/v2/Users/{user.id}"
    created = user.created_at.isoformat() if user.created_at else None
    modified = user.updated_at.isoformat() if user.updated_at else None

    scim_user = {
        "schemas": [SCIM_USER_SCHEMA, SCIM_ENTERPRISE_SCHEMA],
        "id": str(user.id),
        "externalId": getattr(user, "scim_external_id", None),
        "userName": user.email,
        "name": {
            "givenName": user.first_name,
            "familyName": user.last_name,
        },
        "emails": [
            {
                "value": user.email,
                "primary": True,
                "type": "work",
            }
        ],
        "active": user.is_active,
        "roles": [{"value": user.role.value if hasattr(user.role, "value") else user.role}],
        SCIM_ENTERPRISE_SCHEMA: {
            "department": user.role.value if hasattr(user.role, "value") else user.role,
        },
        "meta": {
            "resourceType": "User",
            "created": created,
            "lastModified": modified,
            "location": location,
        },
    }
    return scim_user


def _map_role_from_scim(scim_data: dict) -> str:
    # Check roles array first
    roles = scim_data.get("roles")
    if roles and isinstance(roles, list) and len(roles) > 0:
        role_value = roles[0].get("value", "") if isinstance(roles[0], dict) else str(roles[0])
        role_value = role_value.lower().strip()
        for r in UserRole:
            if r.value == role_value:
                return r.value
        # Map common external role names
        role_map = {
            "administrator": "admin",
            "lawyer": "attorney",
            "partner": "attorney",
            "associate": "attorney",
            "legal_assistant": "paralegal",
            "clerk": "billing_clerk",
            "billing": "billing_clerk",
        }
        if role_value in role_map:
            return role_map[role_value]

    # Check enterprise extension
    enterprise = scim_data.get(SCIM_ENTERPRISE_SCHEMA)
    if enterprise and isinstance(enterprise, dict):
        dept = enterprise.get("department", "")
        if dept:
            dept_lower = dept.lower().strip()
            for r in UserRole:
                if r.value == dept_lower:
                    return r.value

    return "attorney"


def _map_scim_to_user_data(scim_data: dict) -> dict:
    data = {}

    # Email from userName
    username = scim_data.get("userName")
    if username:
        data["email"] = username

    # Also check emails array
    emails = scim_data.get("emails")
    if emails and isinstance(emails, list):
        for email_obj in emails:
            if isinstance(email_obj, dict):
                if email_obj.get("primary", False) or len(emails) == 1:
                    data["email"] = email_obj.get("value", data.get("email", ""))
                    break

    # Name
    name = scim_data.get("name")
    if name and isinstance(name, dict):
        if "givenName" in name:
            data["first_name"] = name["givenName"]
        if "familyName" in name:
            data["last_name"] = name["familyName"]

    # Role
    role = _map_role_from_scim(scim_data)
    data["role"] = role

    # Active status
    if "active" in scim_data:
        data["is_active"] = scim_data["active"]

    # External ID
    if "externalId" in scim_data:
        data["scim_external_id"] = scim_data["externalId"]

    return data


async def list_users(
    db: AsyncSession,
    filter_str: Optional[str],
    start_index: int,
    count: int,
    base_url: str,
) -> dict:
    query = select(User)
    count_query = select(func.count(User.id))

    if filter_str:
        # Parse basic SCIM filter: userName eq "value"
        match = re.match(r'userName\s+eq\s+"([^"]+)"', filter_str.strip())
        if match:
            email_value = match.group(1)
            query = query.where(User.email == email_value)
            count_query = count_query.where(User.email == email_value)

    total = (await db.execute(count_query)).scalar_one()

    # SCIM uses 1-based indexing
    offset = max(0, start_index - 1)
    result = await db.execute(query.order_by(User.created_at.asc()).offset(offset).limit(count))
    users = result.scalars().all()

    resources = [_map_user_to_scim(u, base_url) for u in users]

    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


async def get_user(db: AsyncSession, user_id: uuid.UUID, base_url: str) -> Optional[dict]:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return None
    return _map_user_to_scim(user, base_url)


async def create_user(db: AsyncSession, scim_data: dict, base_url: str) -> dict:
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    user_data = _map_scim_to_user_data(scim_data)

    # Check for existing user with same email
    existing = await db.execute(select(User).where(User.email == user_data.get("email")))
    if existing.scalar_one_or_none():
        raise ValueError("User with this email already exists")

    random_password = str(uuid.uuid4())
    password_hash = pwd_context.hash(random_password)

    user = User(
        email=user_data["email"],
        password_hash=password_hash,
        first_name=user_data.get("first_name", ""),
        last_name=user_data.get("last_name", ""),
        role=UserRole(user_data.get("role", "attorney")),
        is_active=user_data.get("is_active", True),
        scim_external_id=user_data.get("scim_external_id"),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    await create_audit_log(
        db,
        user_id=None,
        entity_type="user",
        entity_id=str(user.id),
        action="scim_create_user",
        changes_json=f'{{"email": "{user.email}", "role": "{user.role.value}"}}',
    )

    return _map_user_to_scim(user, base_url)


async def update_user(db: AsyncSession, user_id: uuid.UUID, scim_data: dict, base_url: str) -> Optional[dict]:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return None

    user_data = _map_scim_to_user_data(scim_data)

    if "email" in user_data:
        user.email = user_data["email"]
    if "first_name" in user_data:
        user.first_name = user_data["first_name"]
    if "last_name" in user_data:
        user.last_name = user_data["last_name"]
    if "role" in user_data:
        user.role = UserRole(user_data["role"])
    if "is_active" in user_data:
        user.is_active = user_data["is_active"]
    if "scim_external_id" in user_data:
        user.scim_external_id = user_data["scim_external_id"]

    await db.flush()
    await db.refresh(user)

    await create_audit_log(
        db,
        user_id=None,
        entity_type="user",
        entity_id=str(user.id),
        action="scim_update_user",
        changes_json=f'{{"email": "{user.email}"}}',
    )

    return _map_user_to_scim(user, base_url)


async def patch_user(db: AsyncSession, user_id: uuid.UUID, operations: list[dict], base_url: str) -> Optional[dict]:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return None

    for op in operations:
        operation = op.get("op", "").lower()
        path = op.get("path", "")
        value = op.get("value")

        if operation == "replace":
            if path == "active" or (not path and isinstance(value, dict) and "active" in value):
                active_val = value if isinstance(value, bool) else value.get("active")
                if isinstance(active_val, bool):
                    user.is_active = active_val
            elif path == "name" or (not path and isinstance(value, dict) and "name" in value):
                name_val = value if path == "name" else value.get("name")
                if isinstance(name_val, dict):
                    if "givenName" in name_val:
                        user.first_name = name_val["givenName"]
                    if "familyName" in name_val:
                        user.last_name = name_val["familyName"]
            elif path == "userName" or (not path and isinstance(value, dict) and "userName" in value):
                username_val = value if isinstance(value, str) else value.get("userName")
                if username_val:
                    user.email = username_val
            elif path == "emails" or (not path and isinstance(value, dict) and "emails" in value):
                emails_val = value if path == "emails" else value.get("emails")
                if isinstance(emails_val, list) and len(emails_val) > 0:
                    email_obj = emails_val[0]
                    if isinstance(email_obj, dict) and "value" in email_obj:
                        user.email = email_obj["value"]
            elif not path and isinstance(value, dict):
                # Bulk replace: process all known attributes
                if "active" in value and isinstance(value["active"], bool):
                    user.is_active = value["active"]
                if "name" in value and isinstance(value["name"], dict):
                    if "givenName" in value["name"]:
                        user.first_name = value["name"]["givenName"]
                    if "familyName" in value["name"]:
                        user.last_name = value["name"]["familyName"]
                if "userName" in value:
                    user.email = value["userName"]
                if "emails" in value and isinstance(value["emails"], list) and len(value["emails"]) > 0:
                    email_obj = value["emails"][0]
                    if isinstance(email_obj, dict) and "value" in email_obj:
                        user.email = email_obj["value"]

        elif operation == "add":
            if path == "emails" and isinstance(value, list):
                for email_obj in value:
                    if isinstance(email_obj, dict) and email_obj.get("primary"):
                        user.email = email_obj["value"]

        elif operation == "remove":
            if path == "active":
                user.is_active = False

    await db.flush()
    await db.refresh(user)

    await create_audit_log(
        db,
        user_id=None,
        entity_type="user",
        entity_id=str(user.id),
        action="scim_patch_user",
        changes_json=f'{{"email": "{user.email}"}}',
    )

    return _map_user_to_scim(user, base_url)


async def delete_user(db: AsyncSession, user_id: uuid.UUID) -> bool:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return False

    user.is_active = False
    await db.flush()

    await create_audit_log(
        db,
        user_id=None,
        entity_type="user",
        entity_id=str(user.id),
        action="scim_deactivate_user",
        changes_json=f'{{"email": "{user.email}", "is_active": false}}',
    )

    return True


async def create_bearer_token(
    db: AsyncSession,
    description: str,
    expires_in_days: Optional[int],
    created_by: uuid.UUID,
) -> tuple[ScimBearerToken, str]:
    plaintext_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plaintext_token.encode("utf-8")).hexdigest()

    expires_at = None
    if expires_in_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

    token_record = ScimBearerToken(
        token_hash=token_hash,
        description=description,
        created_by=created_by,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(token_record)
    await db.flush()
    await db.refresh(token_record)

    return token_record, plaintext_token


async def list_bearer_tokens(db: AsyncSession) -> list[ScimBearerToken]:
    result = await db.execute(select(ScimBearerToken).order_by(ScimBearerToken.created_at.desc()))
    return list(result.scalars().all())


async def revoke_bearer_token(db: AsyncSession, token_id: uuid.UUID) -> bool:
    result = await db.execute(select(ScimBearerToken).where(ScimBearerToken.id == token_id))
    token_record = result.scalar_one_or_none()
    if token_record is None:
        return False

    token_record.is_active = False
    await db.flush()
    return True
