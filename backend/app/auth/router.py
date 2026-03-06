import json
import uuid as _uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User
from app.auth.schemas import (
    LoginRequest,
    LoginResponse,
    PasswordChange,
    RefreshRequest,
    TokenResponse,
    TwoFactorLoginRequest,
    TwoFactorSetupResponse,
    TwoFactorStatusResponse,
    TwoFactorVerifyRequest,
    TwoFactorVerifySetupResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
    WebAuthnAuthBeginRequest,
    WebAuthnAuthBeginResponse,
    WebAuthnAuthCompleteRequest,
    WebAuthnCredentialResponse,
    WebAuthnRegistrationBeginResponse,
    WebAuthnRegistrationCompleteRequest,
    WebAuthnRegistrationCompleteResponse,
)
from app.auth.service import (
    authenticate_user,
    create_2fa_pending_token,
    create_access_token,
    create_audit_log,
    create_refresh_token,
    create_user,
    delete_webauthn_credential,
    disable_2fa,
    get_user_webauthn_credentials,
    hash_password,
    rotate_refresh_token,
    setup_2fa,
    verify_2fa_pending_token,
    verify_2fa_setup,
    verify_password,
    verify_recovery_code,
    verify_totp_code,
    webauthn_auth_begin,
    webauthn_auth_complete,
    webauthn_registration_begin,
    webauthn_registration_complete,
)
from app.common.pagination import PaginatedResponse, PaginationParams
from app.common.rate_limit import rate_limit_2fa, rate_limit_login, reset_login_rate_limit
from app.database import get_db
from app.dependencies import get_current_user, require_roles

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
async def login(data: LoginRequest, request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    rate_limit_login(request)
    user = await authenticate_user(db, data.email, data.password)
    if user is None:
        # Commit to persist failed-login counter / lockout state before
        # raising, because the dependency's exception handler will rollback.
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Successful auth — clear rate limit for this IP
    reset_login_rate_limit(request)

    # If any MFA method is enabled, return a temporary token instead of full credentials
    mfa_methods: list[str] = []
    if user.totp_enabled:
        mfa_methods.append("totp")
    if user.webauthn_enabled:
        mfa_methods.append("webauthn")

    if mfa_methods:
        temp_token = create_2fa_pending_token(str(user.id))
        await create_audit_log(
            db,
            user.id,
            "user",
            str(user.id),
            "login_2fa_pending",
            ip_address=request.client.host if request.client else None,
        )
        return LoginResponse(requires_2fa=True, temp_token=temp_token, mfa_methods=mfa_methods)

    access_token = create_access_token(str(user.id), user.role.value)
    refresh_token = await create_refresh_token(db, user.id)

    await create_audit_log(
        db, user.id, "user", str(user.id), "login", ip_address=request.client.host if request.client else None
    )

    return LoginResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(data: RefreshRequest, db: Annotated[AsyncSession, Depends(get_db)]):
    result = await rotate_refresh_token(db, data.refresh_token)
    if result is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    user, new_refresh = result
    access_token = create_access_token(str(user.id), user.role.value)
    return TokenResponse(access_token=access_token, refresh_token=new_refresh)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


@router.put("/me/password")
async def change_password(
    data: PasswordChange,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not verify_password(data.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    current_user.password_hash = hash_password(data.new_password)

    # Revoke all existing refresh tokens (force re-login on other devices)
    from app.auth.models import RefreshToken

    tokens_result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    for token in tokens_result.scalars().all():
        token.revoked = True

    await db.flush()
    return {"message": "Password updated. Please log in again on other devices."}


# ── Two-Factor Authentication ─────────────────────────────────────


@router.post("/2fa/verify", response_model=LoginResponse)
async def verify_2fa_login(data: TwoFactorLoginRequest, request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    """Verify a TOTP code (or recovery code) to complete 2FA login."""
    rate_limit_2fa(request)
    user_id = verify_2fa_pending_token(data.temp_token)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired 2FA token")

    result = await db.execute(select(User).where(User.id == _uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled for this user")

    code = data.code.strip()

    # Try TOTP code first
    if verify_totp_code(user.totp_secret, code):
        access_token = create_access_token(str(user.id), user.role.value)
        refresh_token = await create_refresh_token(db, user.id)
        await create_audit_log(
            db,
            user.id,
            "user",
            str(user.id),
            "login_2fa_verified",
            ip_address=request.client.host if request.client else None,
        )
        return LoginResponse(access_token=access_token, refresh_token=refresh_token)

    # Try recovery code
    if user.recovery_codes:
        valid, updated_hashes = verify_recovery_code(user.recovery_codes, code)
        if valid:
            user.recovery_codes = updated_hashes
            await db.flush()
            access_token = create_access_token(str(user.id), user.role.value)
            refresh_token = await create_refresh_token(db, user.id)
            await create_audit_log(
                db,
                user.id,
                "user",
                str(user.id),
                "login_2fa_recovery_code",
                changes_json=json.dumps({"recovery_code_used": True}),
                ip_address=request.client.host if request.client else None,
            )
            return LoginResponse(access_token=access_token, refresh_token=refresh_token)

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code")


@router.get("/2fa/status", response_model=TwoFactorStatusResponse)
async def get_2fa_status(current_user: Annotated[User, Depends(get_current_user)]):
    """Check if 2FA is enabled for the current user."""
    return TwoFactorStatusResponse(enabled=current_user.totp_enabled)


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa_endpoint(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Initialize 2FA setup — generates secret, provisioning URI, and QR code."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled. Disable it first.")

    result = await setup_2fa(db, current_user)
    await create_audit_log(
        db,
        current_user.id,
        "user",
        str(current_user.id),
        "2fa_setup_initiated",
        ip_address=request.client.host if request.client else None,
    )
    return TwoFactorSetupResponse(**result)


@router.post("/2fa/setup/verify", response_model=TwoFactorVerifySetupResponse)
async def verify_2fa_setup_endpoint(
    data: TwoFactorVerifyRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Verify the TOTP setup with a code from the authenticator app. Returns recovery codes."""
    try:
        result = await verify_2fa_setup(db, current_user, data.code)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await create_audit_log(
        db,
        current_user.id,
        "user",
        str(current_user.id),
        "2fa_enabled",
        ip_address=request.client.host if request.client else None,
    )
    return TwoFactorVerifySetupResponse(recovery_codes=result["recovery_codes"])


@router.post("/2fa/disable")
async def disable_2fa_endpoint(
    data: TwoFactorVerifyRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Disable 2FA after verifying the current TOTP code."""
    try:
        await disable_2fa(db, current_user, data.code)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await create_audit_log(
        db,
        current_user.id,
        "user",
        str(current_user.id),
        "2fa_disabled",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Two-factor authentication has been disabled"}


# ── WebAuthn / FIDO2 ───────────────────────────────────────────────


@router.post("/webauthn/register/begin", response_model=WebAuthnRegistrationBeginResponse)
async def webauthn_register_begin(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
):
    try:
        options = await webauthn_registration_begin(current_user)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return WebAuthnRegistrationBeginResponse(options=options)


@router.post("/webauthn/register/complete", response_model=WebAuthnRegistrationCompleteResponse)
async def webauthn_register_complete_endpoint(
    data: WebAuthnRegistrationCompleteRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        credential = await webauthn_registration_complete(current_user, data.credential, data.name, db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await create_audit_log(
        db,
        current_user.id,
        "user",
        str(current_user.id),
        "webauthn_registered",
        changes_json=json.dumps({"credential_name": data.name}),
        ip_address=request.client.host if request.client else None,
    )

    return WebAuthnRegistrationCompleteResponse(
        id=str(credential.id),
        name=credential.name,
        created_at=credential.created_at,
    )


@router.post("/webauthn/authenticate/begin", response_model=WebAuthnAuthBeginResponse)
async def webauthn_authenticate_begin(
    data: WebAuthnAuthBeginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user_id = verify_2fa_pending_token(data.temp_token)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired 2FA token")

    result = await db.execute(select(User).where(User.id == _uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    if not user.webauthn_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="WebAuthn is not enabled for this user")

    try:
        options = await webauthn_auth_begin(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return WebAuthnAuthBeginResponse(options=options)


@router.post("/webauthn/authenticate/complete", response_model=LoginResponse)
async def webauthn_authenticate_complete(
    data: WebAuthnAuthCompleteRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user_id = verify_2fa_pending_token(data.temp_token)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired 2FA token")

    result = await db.execute(select(User).where(User.id == _uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    try:
        await webauthn_auth_complete(user, data.credential, db)
    except ValueError as e:
        await create_audit_log(
            db,
            user.id,
            "user",
            str(user.id),
            "webauthn_login_failed",
            changes_json=json.dumps({"error": str(e)}),
            ip_address=request.client.host if request.client else None,
            outcome="failure",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        await create_audit_log(
            db,
            user.id,
            "user",
            str(user.id),
            "webauthn_login_failed",
            changes_json=json.dumps({"error": str(e)}),
            ip_address=request.client.host if request.client else None,
            outcome="failure",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="WebAuthn verification failed")

    access_token = create_access_token(str(user.id), user.role.value)
    refresh_token = await create_refresh_token(db, user.id)

    await create_audit_log(
        db,
        user.id,
        "user",
        str(user.id),
        "webauthn_login",
        ip_address=request.client.host if request.client else None,
    )

    return LoginResponse(access_token=access_token, refresh_token=refresh_token)


@router.get("/webauthn/credentials", response_model=list[WebAuthnCredentialResponse])
async def list_webauthn_credentials(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    credentials = await get_user_webauthn_credentials(current_user.id, db)
    return [
        WebAuthnCredentialResponse(
            id=str(c.id),
            name=c.name,
            transports=c.transports,
            created_at=c.created_at,
        )
        for c in credentials
    ]


@router.delete("/webauthn/credentials/{credential_id}")
async def delete_webauthn_credential_endpoint(
    credential_id: str,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        await delete_webauthn_credential(_uuid.UUID(credential_id), current_user.id, db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    await create_audit_log(
        db,
        current_user.id,
        "user",
        str(current_user.id),
        "webauthn_removed",
        changes_json=json.dumps({"credential_id": credential_id}),
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "WebAuthn credential removed"}


# Admin-only user management
@router.get("/users", response_model=PaginatedResponse)
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
    page: int = 1,
    page_size: int = 25,
):
    pagination = PaginationParams(page=page, page_size=page_size)
    count_result = await db.execute(select(func.count(User.id)))
    total = count_result.scalar_one()

    result = await db.execute(
        select(User).order_by(User.last_name, User.first_name).offset(pagination.offset).limit(pagination.page_size)
    )
    users = result.scalars().all()
    items = [UserResponse.model_validate(u) for u in users]
    return PaginatedResponse.create(
        items=[i.model_dump() for i in items], total=total, page=pagination.page, page_size=pagination.page_size
    )


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_new_user(
    data: UserCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    # Check for existing email
    existing = await db.execute(select(User).where(User.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = await create_user(db, data)
    await create_audit_log(
        db,
        admin.id,
        "user",
        str(user.id),
        "create",
        changes_json=json.dumps({"email": data.email, "role": data.role.value}),
        ip_address=request.client.host if request.client else None,
    )
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    data: UserUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    result = await db.execute(select(User).where(User.id == _uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    changes = {}
    for field, value in data.model_dump(exclude_unset=True).items():
        old_value = getattr(user, field)
        if field == "role" and value is not None:
            value_str = value.value if hasattr(value, "value") else value
            old_str = old_value.value if hasattr(old_value, "value") else old_value
            if value_str != old_str:
                changes[field] = {"old": old_str, "new": value_str}
            setattr(user, field, value)
        elif value is not None and value != old_value:
            changes[field] = {"old": str(old_value), "new": str(value)}
            setattr(user, field, value)

    if changes:
        await create_audit_log(
            db,
            admin.id,
            "user",
            str(user.id),
            "update",
            changes_json=json.dumps(changes),
            ip_address=request.client.host if request.client else None,
        )

    await db.flush()
    await db.refresh(user)
    return user
