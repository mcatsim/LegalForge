import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import jwt as jose_jwt
from jwt import PyJWKClient
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User, UserRole
from app.auth.service import create_access_token, create_refresh_token, hash_password
from app.common.encryption import decrypt_field as decrypt_value
from app.common.encryption import encrypt_field as encrypt_value
from app.config import settings
from app.sso.models import SSOProvider, SSOSession

logger = logging.getLogger(__name__)


def mask_secret(encrypted_secret: Optional[str]) -> Optional[str]:
    """Return a masked version of the client secret for display."""
    if not encrypted_secret:
        return None
    try:
        decrypted = decrypt_value(encrypted_secret)
        if len(decrypted) <= 4:
            return "****"
        return "****" + decrypted[-4:]
    except Exception:
        return "****"


# ── CRUD Operations ──────────────────────────────────────────────────


async def create_sso_provider(db: AsyncSession, data: dict, created_by: Optional[uuid.UUID] = None) -> SSOProvider:
    provider = SSOProvider(
        name=data["name"],
        provider_type=data.get("provider_type", "oidc"),
        client_id=data.get("client_id"),
        discovery_url=data.get("discovery_url"),
        scopes=data.get("scopes", "openid email profile"),
        email_claim=data.get("email_claim", "email"),
        name_claim=data.get("name_claim", "name"),
        role_mapping=data.get("role_mapping"),
        auto_create_users=data.get("auto_create_users", True),
        default_role=data.get("default_role", "paralegal"),
        saml_entity_id=data.get("saml_entity_id"),
        saml_sso_url=data.get("saml_sso_url"),
        saml_certificate=data.get("saml_certificate"),
        saml_sp_entity_id=data.get("saml_sp_entity_id"),
        saml_idp_metadata_url=data.get("saml_idp_metadata_url"),
        saml_idp_metadata_xml=data.get("saml_idp_metadata_xml"),
        saml_name_id_format=data.get("saml_name_id_format", "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"),
        saml_sign_requests=data.get("saml_sign_requests", False),
        saml_sp_certificate=data.get("saml_sp_certificate"),
        saml_attribute_mapping=data.get("saml_attribute_mapping"),
        saml_want_assertions_signed=data.get("saml_want_assertions_signed", True),
        created_by=created_by,
    )

    # Encrypt client_secret if provided
    client_secret = data.get("client_secret")
    if client_secret:
        provider.client_secret_encrypted = encrypt_value(client_secret)

    # Encrypt SAML SP private key if provided
    saml_sp_private_key = data.get("saml_sp_private_key")
    if saml_sp_private_key:
        provider.saml_sp_private_key_encrypted = encrypt_value(saml_sp_private_key)

    db.add(provider)
    await db.flush()
    await db.refresh(provider)
    return provider


async def get_sso_provider(db: AsyncSession, provider_id: uuid.UUID) -> Optional[SSOProvider]:
    """Get a single SSO provider by ID."""
    result = await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))
    return result.scalar_one_or_none()


async def list_sso_providers(db: AsyncSession) -> list[SSOProvider]:
    """List all SSO providers."""
    result = await db.execute(select(SSOProvider).order_by(SSOProvider.name))
    return list(result.scalars().all())


async def list_active_sso_providers(db: AsyncSession) -> list[SSOProvider]:
    """List only active SSO providers (for public display on login page)."""
    result = await db.execute(
        select(SSOProvider).where(SSOProvider.is_active == True).order_by(SSOProvider.name)  # noqa: E712
    )
    return list(result.scalars().all())


async def update_sso_provider(db: AsyncSession, provider: SSOProvider, data: dict) -> SSOProvider:
    for field, value in data.items():
        if field == "client_secret" and value is not None:
            provider.client_secret_encrypted = encrypt_value(value)
        elif field == "client_secret":
            continue
        elif field == "saml_sp_private_key" and value is not None:
            provider.saml_sp_private_key_encrypted = encrypt_value(value)
        elif field == "saml_sp_private_key":
            continue
        elif hasattr(provider, field) and value is not None:
            setattr(provider, field, value)

    # If setting as default, unset other defaults
    if data.get("is_default"):
        await db.execute(update(SSOProvider).where(SSOProvider.id != provider.id).values(is_default=False))

    await db.flush()
    await db.refresh(provider)
    return provider


async def delete_sso_provider(db: AsyncSession, provider: SSOProvider) -> None:
    """Delete an SSO provider."""
    await db.delete(provider)
    await db.flush()


# ── OIDC Discovery ───────────────────────────────────────────────────


async def discover_oidc_endpoints(discovery_url: str) -> dict[str, str]:
    """Fetch OIDC discovery document and extract endpoints."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        doc = resp.json()

    return {
        "authorization_endpoint": doc.get("authorization_endpoint", ""),
        "token_endpoint": doc.get("token_endpoint", ""),
        "userinfo_endpoint": doc.get("userinfo_endpoint", ""),
        "jwks_uri": doc.get("jwks_uri", ""),
    }


async def apply_discovery_to_provider(db: AsyncSession, provider: SSOProvider) -> SSOProvider:
    """Fetch discovery document and update provider endpoints."""
    if not provider.discovery_url:
        raise ValueError("No discovery_url configured for this provider")

    endpoints = await discover_oidc_endpoints(provider.discovery_url)
    provider.authorization_endpoint = endpoints["authorization_endpoint"]
    provider.token_endpoint = endpoints["token_endpoint"]
    provider.userinfo_endpoint = endpoints["userinfo_endpoint"]
    provider.jwks_uri = endpoints["jwks_uri"]

    await db.flush()
    await db.refresh(provider)
    return provider


# ── SSO Login Flow ───────────────────────────────────────────────────


async def get_default_provider(db: AsyncSession) -> Optional[SSOProvider]:
    """Get the default SSO provider."""
    result = await db.execute(
        select(SSOProvider).where(
            SSOProvider.is_default == True,  # noqa: E712
            SSOProvider.is_active == True,  # noqa: E712
        )
    )
    return result.scalar_one_or_none()


async def initiate_sso_login(db: AsyncSession, provider: SSOProvider) -> tuple[str, str]:
    if provider.provider_type == "saml" or provider.provider_type.value == "saml":
        return await initiate_saml_login(db, provider)

    if not provider.authorization_endpoint:
        raise ValueError("Provider has no authorization_endpoint configured. Run discovery first.")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Create SSO session to track state
    sso_session = SSOSession(
        provider_id=provider.id,
        state=state,
        nonce=nonce,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(sso_session)
    await db.flush()

    # Build the authorization URL
    callback_url = settings.sso_redirect_uri
    scopes = provider.scopes or "openid email profile"

    params = {
        "response_type": "code",
        "client_id": provider.client_id or "",
        "redirect_uri": callback_url,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
    }

    # Use httpx to properly build the URL with query parameters
    redirect_url = str(
        httpx.URL(provider.authorization_endpoint).copy_with(
            params=params,
        )
    )

    return redirect_url, state


# ── SAML Functions ───────────────────────────────────────────────────


def _build_saml_settings(provider: SSOProvider) -> dict:
    base_url = settings.sso_redirect_uri.rsplit("/callback", 1)[0]
    acs_url = f"{base_url}/saml/callback"
    sp_entity_id = provider.saml_sp_entity_id or f"{base_url}/saml/metadata/{provider.id}"

    idp_settings = {}

    # Try parsing IdP metadata first
    if provider.saml_idp_metadata_url:
        idp_settings = OneLogin_Saml2_IdPMetadataParser.parse_remote(provider.saml_idp_metadata_url)
    elif provider.saml_idp_metadata_xml:
        idp_settings = OneLogin_Saml2_IdPMetadataParser.parse(provider.saml_idp_metadata_xml)

    # Build IdP config from parsed metadata or individual fields
    if "idp" in idp_settings:
        idp_config = idp_settings["idp"]
    else:
        idp_config = {
            "entityId": provider.saml_entity_id or "",
            "singleSignOnService": {
                "url": provider.saml_sso_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
        }
        if provider.saml_certificate:
            idp_config["x509cert"] = provider.saml_certificate

    # Build SP config
    sp_config = {
        "entityId": sp_entity_id,
        "assertionConsumerService": {
            "url": acs_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "NameIDFormat": provider.saml_name_id_format or "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
    }

    if provider.saml_sp_certificate:
        sp_config["x509cert"] = provider.saml_sp_certificate

    if provider.saml_sp_private_key_encrypted:
        sp_config["privateKey"] = decrypt_value(provider.saml_sp_private_key_encrypted)

    saml_settings = {
        "strict": True,
        "debug": settings.debug,
        "sp": sp_config,
        "idp": idp_config,
        "security": {
            "authnRequestsSigned": provider.saml_sign_requests or False,
            "wantAssertionsSigned": provider.saml_want_assertions_signed
            if provider.saml_want_assertions_signed is not None
            else True,
            "wantNameIdEncrypted": False,
        },
    }

    return saml_settings


def _prepare_saml_request_data(url: str, post_data: Optional[dict] = None) -> dict:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return {
        "https": "on" if parsed.scheme == "https" else "off",
        "http_host": parsed.hostname or "localhost",
        "server_port": str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80"),
        "script_name": parsed.path,
        "get_data": {},
        "post_data": post_data or {},
    }


async def initiate_saml_login(db: AsyncSession, provider: SSOProvider) -> tuple[str, str]:
    saml_settings = _build_saml_settings(provider)
    settings.sso_redirect_uri.rsplit("/callback", 1)[0]
    acs_url = saml_settings["sp"]["assertionConsumerService"]["url"]
    request_data = _prepare_saml_request_data(acs_url)

    auth = OneLogin_Saml2_Auth(request_data, saml_settings)

    # Use provider_id as RelayState so the callback can find the provider
    relay_state = str(provider.id)
    redirect_url = auth.login(return_to=relay_state)

    # Create SSO session to track the login attempt
    state = secrets.token_urlsafe(32)
    sso_session = SSOSession(
        provider_id=provider.id,
        state=state,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(sso_session)
    await db.flush()

    return redirect_url, state


async def handle_saml_callback(
    saml_response_data: dict,
    provider: SSOProvider,
    db: AsyncSession,
) -> tuple:

    saml_settings = _build_saml_settings(provider)
    settings.sso_redirect_uri.rsplit("/callback", 1)[0]
    acs_url = saml_settings["sp"]["assertionConsumerService"]["url"]

    request_data = _prepare_saml_request_data(acs_url, post_data=saml_response_data)

    auth = OneLogin_Saml2_Auth(request_data, saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        error_reason = auth.get_last_error_reason() or ", ".join(errors)
        logger.warning("SAML response validation failed: %s", error_reason)
        raise ValueError(f"SAML authentication failed: {error_reason}")

    if not auth.is_authenticated():
        raise ValueError("SAML authentication was not successful")

    # Extract NameID and attributes
    name_id = auth.get_nameid()
    attributes = auth.get_attributes()
    auth.get_session_index()

    # Map attributes to user fields using attribute_mapping or defaults
    attr_mapping = provider.saml_attribute_mapping or {}
    email_attr = attr_mapping.get("email", provider.email_claim or "email")
    name_attr = attr_mapping.get("name", provider.name_claim or "name")
    groups_attr = attr_mapping.get("groups", "groups")

    # Try to get email from attributes first, then fall back to NameID
    email = None
    if email_attr in attributes:
        email_values = attributes[email_attr]
        email = email_values[0] if email_values else None
    if not email:
        email = name_id

    if not email:
        raise ValueError("Could not extract email from SAML response")

    # Get full name from attributes
    full_name = ""
    if name_attr in attributes:
        name_values = attributes[name_attr]
        full_name = name_values[0] if name_values else ""

    # Build claims dict for compatibility with _find_or_create_user
    claims = {"email": email, "name": full_name, "sub": name_id}
    if groups_attr in attributes:
        claims["groups"] = attributes[groups_attr]

    # Find or create user
    user = await _find_or_create_user(db, provider, email, full_name, claims)

    # Create/update SSO session
    sso_session = SSOSession(
        provider_id=provider.id,
        user_id=user.id,
        external_id=name_id or "",
        state=secrets.token_urlsafe(32),
        id_token_claims=claims,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
    )
    db.add(sso_session)
    await db.flush()

    # Issue app JWT tokens
    access_token = create_access_token(str(user.id), user.role.value)
    refresh_token = await create_refresh_token(db, user.id)

    return user, access_token, refresh_token


def generate_sp_metadata(provider: SSOProvider) -> str:
    saml_settings = _build_saml_settings(provider)
    settings.sso_redirect_uri.rsplit("/callback", 1)[0]
    acs_url = saml_settings["sp"]["assertionConsumerService"]["url"]

    request_data = _prepare_saml_request_data(acs_url)
    auth = OneLogin_Saml2_Auth(request_data, saml_settings)
    metadata = auth.get_settings().get_sp_metadata()

    errors = auth.get_settings().validate_metadata(metadata)
    if errors:
        logger.warning("SP metadata validation errors: %s", errors)

    return metadata


async def _decode_id_token(id_token: str, jwks_uri: Optional[str], client_id: str) -> dict:
    """Decode and verify an OIDC id_token using the provider's JWKS.

    Raises ValueError if the token cannot be verified.
    """
    if not jwks_uri:
        raise ValueError("Cannot verify id_token: no JWKS URI configured for this provider")

    try:
        jwks_client = PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = jose_jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=client_id,
            options={"verify_exp": True},
        )
        return claims
    except Exception as e:
        raise ValueError(f"id_token signature verification failed: {e}")


async def _consume_sso_state(db: AsyncSession, state: str) -> SSOSession:
    """Validate and delete the SSO state parameter in one operation.

    Raises ValueError if the state is invalid, expired, or already used.
    """
    result = await db.execute(select(SSOSession).where(SSOSession.state == state).with_for_update())
    sso_session = result.scalar_one_or_none()

    if sso_session is None:
        raise ValueError("Invalid or expired SSO state parameter")

    # Check expiration
    if sso_session.expires_at:
        expires = sso_session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            await db.delete(sso_session)
            raise ValueError("SSO session has expired")

    # Consume: delete the session so it cannot be reused
    await db.delete(sso_session)
    await db.flush()

    # Return the session (detached) with the info we need
    return sso_session


async def handle_sso_callback(db: AsyncSession, code: str, state: str) -> tuple[User, str, str]:
    """
    Handle the SSO callback from the IdP.

    Validates state, exchanges code for tokens, extracts user claims,
    finds or creates the user, and issues app JWT tokens.

    Returns (user, access_token, refresh_token_value).
    """
    # 1. Validate and consume the state parameter (one-time use)
    sso_session = await _consume_sso_state(db, state)

    # 2. Get the provider
    provider_result = await db.execute(select(SSOProvider).where(SSOProvider.id == sso_session.provider_id))
    provider = provider_result.scalar_one_or_none()
    if provider is None:
        raise ValueError("SSO provider not found")

    if not provider.token_endpoint:
        raise ValueError("Provider has no token_endpoint configured")

    # 3. Exchange authorization code for tokens
    client_secret = ""
    if provider.client_secret_encrypted:
        client_secret = decrypt_value(provider.client_secret_encrypted)

    callback_url = settings.sso_redirect_uri

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": callback_url,
        "client_id": provider.client_id or "",
        "client_secret": client_secret,
    }

    async with httpx.AsyncClient(timeout=15.0) as http_client:
        token_resp = await http_client.post(
            provider.token_endpoint,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_resp.raise_for_status()
        token_json = token_resp.json()

    id_token = token_json.get("id_token")
    access_token_idp = token_json.get("access_token")

    # 4. Extract user claims from id_token or userinfo endpoint
    claims: dict = {}

    if id_token:
        try:
            claims = await _decode_id_token(
                id_token,
                jwks_uri=provider.jwks_uri,
                client_id=provider.client_id or "",
            )
        except ValueError:
            # If JWKS verification fails, fall back to userinfo endpoint only
            # (the access_token was obtained directly from the IdP over TLS)
            claims = {}

    # If we don't have enough claims, try the userinfo endpoint
    email_claim = provider.email_claim or "email"
    name_claim = provider.name_claim or "name"

    if not claims.get(email_claim) and provider.userinfo_endpoint and access_token_idp:
        async with httpx.AsyncClient(timeout=15.0) as http_client:
            userinfo_resp = await http_client.get(
                provider.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token_idp}"},
            )
            if userinfo_resp.status_code == 200:
                userinfo = userinfo_resp.json()
                claims.update(userinfo)

    email = claims.get(email_claim)
    if not email:
        raise ValueError("Could not extract email from IdP response")

    full_name = claims.get(name_claim, "")
    external_id = claims.get("sub", "")

    # 5. Find or create user
    user = await _find_or_create_user(db, provider, email, full_name, claims)

    # 6. Create new SSO session for the authenticated user
    new_sso_session = SSOSession(
        provider_id=sso_session.provider_id,
        user_id=user.id,
        external_id=external_id,
        state=secrets.token_urlsafe(32),
        id_token_claims=claims,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
    )
    db.add(new_sso_session)
    await db.flush()

    # 7. Issue app JWT tokens
    app_access_token = create_access_token(str(user.id), user.role.value)
    app_refresh_token = await create_refresh_token(db, user.id)

    return user, app_access_token, app_refresh_token


async def _find_or_create_user(
    db: AsyncSession,
    provider: SSOProvider,
    email: str,
    full_name: str,
    claims: dict,
) -> User:
    """Find an existing user by email, or create one if auto_create_users is enabled."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is not None:
        # Apply role mapping if applicable
        _apply_role_mapping(user, provider, claims)
        await db.flush()
        return user

    # User doesn't exist
    if not provider.auto_create_users:
        raise ValueError(f"User {email} not found and auto-creation is disabled for this provider")

    # Parse name
    first_name = full_name.split(" ")[0] if full_name else email.split("@")[0]
    last_name = " ".join(full_name.split(" ")[1:]) if full_name and " " in full_name else ""

    # Determine role
    role_str = provider.default_role or "paralegal"
    try:
        role = UserRole(role_str)
    except ValueError:
        role = UserRole.paralegal

    # Apply role mapping from IdP groups
    if provider.role_mapping and claims:
        groups = claims.get("groups", [])
        if not isinstance(groups, list):
            groups = []
        for group_name, mapped_role in provider.role_mapping.items():
            if group_name in groups:
                try:
                    role = UserRole(mapped_role)
                except ValueError:
                    pass
                break

    # Create the user with a random password (they'll use SSO to log in)
    random_password = secrets.token_urlsafe(32)

    user = User(
        email=email,
        password_hash=hash_password(random_password),
        first_name=first_name,
        last_name=last_name or "SSO",
        role=role,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


def _apply_role_mapping(user: User, provider: SSOProvider, claims: dict) -> None:
    """Apply role mapping from IdP groups to the user if configured."""
    if not provider.role_mapping or not claims:
        return

    groups = claims.get("groups", [])
    if not isinstance(groups, list):
        return

    for group_name, mapped_role in provider.role_mapping.items():
        if group_name in groups:
            try:
                user.role = UserRole(mapped_role)
            except ValueError:
                pass
            break


# ── Connection Test ──────────────────────────────────────────────────


async def test_provider_connection(provider: SSOProvider) -> dict[str, str]:
    """Test an SSO provider's connection by fetching the discovery document."""
    if not provider.discovery_url:
        return {"status": "error", "message": "No discovery_url configured"}

    try:
        endpoints = await discover_oidc_endpoints(provider.discovery_url)
        missing = [k for k, v in endpoints.items() if not v]
        if missing:
            return {
                "status": "warning",
                "message": f"Discovery succeeded but missing endpoints: {', '.join(missing)}",
            }
        return {"status": "ok", "message": "Connection successful. All endpoints discovered."}
    except httpx.HTTPError as e:
        return {"status": "error", "message": f"HTTP error fetching discovery document: {e}"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {e}"}
