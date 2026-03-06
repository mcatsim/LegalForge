import hashlib
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.scim.models import ScimBearerToken

scim_bearer = HTTPBearer()


async def get_scim_client(
    credentials: HTTPAuthorizationCredentials = Depends(scim_bearer),
    db: AsyncSession = Depends(get_db),
) -> ScimBearerToken:
    token_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()

    result = await db.execute(select(ScimBearerToken).where(ScimBearerToken.token_hash == token_hash))
    token_record = result.scalar_one_or_none()

    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SCIM bearer token",
            headers={"Content-Type": "application/scim+json"},
        )

    if not token_record.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SCIM bearer token has been revoked",
            headers={"Content-Type": "application/scim+json"},
        )

    if token_record.expires_at is not None:
        now = datetime.now(timezone.utc)
        expires = token_record.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now > expires:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="SCIM bearer token has expired",
                headers={"Content-Type": "application/scim+json"},
            )

    token_record.last_used_at = datetime.now(timezone.utc)
    await db.flush()

    return token_record
