import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from app.auth.models import UserRole


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    role: UserRole = UserRole.attorney


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    first_name: str
    last_name: str
    role: UserRole
    is_active: bool
    webauthn_enabled: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


# Two-Factor Authentication schemas


class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    requires_2fa: bool = False
    temp_token: Optional[str] = None
    mfa_methods: Optional[list[str]] = None


class TwoFactorSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_base64: str


class TwoFactorVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class TwoFactorVerifySetupResponse(BaseModel):
    recovery_codes: list[str]


class TwoFactorLoginRequest(BaseModel):
    temp_token: str
    code: str = Field(min_length=6, max_length=8)


class TwoFactorStatusResponse(BaseModel):
    enabled: bool


# WebAuthn / FIDO2 schemas


class WebAuthnRegistrationBeginResponse(BaseModel):
    options: dict


class WebAuthnRegistrationCompleteRequest(BaseModel):
    credential: dict
    name: str = Field(min_length=1, max_length=200)


class WebAuthnRegistrationCompleteResponse(BaseModel):
    id: str
    name: str
    created_at: datetime


class WebAuthnAuthBeginRequest(BaseModel):
    temp_token: str


class WebAuthnAuthBeginResponse(BaseModel):
    options: dict


class WebAuthnAuthCompleteRequest(BaseModel):
    temp_token: str
    credential: dict


class WebAuthnCredentialResponse(BaseModel):
    id: str
    name: str
    transports: Optional[list[str]] = None
    created_at: datetime


class WebAuthnCredentialName(BaseModel):
    name: str = Field(min_length=1, max_length=200)
