import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.scim import service as scim_service
from app.scim.auth import get_scim_client
from app.scim.models import ScimBearerToken

router = APIRouter()

SCIM_CONTENT_TYPE = "application/scim+json"


def _scim_response(data: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=data, status_code=status_code, media_type=SCIM_CONTENT_TYPE)


def _scim_error(status_code: int, detail: str, scim_type: Optional[str] = None) -> JSONResponse:
    error = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status_code),
        "detail": detail,
    }
    if scim_type:
        error["scimType"] = scim_type
    return JSONResponse(content=error, status_code=status_code, media_type=SCIM_CONTENT_TYPE)


def _get_base_url(request: Request) -> str:
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"{scheme}://{host}/api/scim"


@router.get("/v2/Users")
async def list_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: ScimBearerToken = Depends(get_scim_client),
    filter: Optional[str] = None,
    startIndex: int = 1,
    count: int = 100,
):
    base_url = _get_base_url(request)
    result = await scim_service.list_users(db, filter, startIndex, count, base_url)
    return _scim_response(result)


@router.get("/v2/Users/{user_id}")
async def get_user(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: ScimBearerToken = Depends(get_scim_client),
):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return _scim_error(400, "Invalid user ID format")

    base_url = _get_base_url(request)
    result = await scim_service.get_user(db, uid, base_url)
    if result is None:
        return _scim_error(404, f"User {user_id} not found")
    return _scim_response(result)


@router.post("/v2/Users")
async def create_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: ScimBearerToken = Depends(get_scim_client),
):
    scim_data = await request.json()
    base_url = _get_base_url(request)
    try:
        result = await scim_service.create_user(db, scim_data, base_url)
    except ValueError as e:
        return _scim_error(409, str(e), scim_type="uniqueness")
    return _scim_response(result, status_code=201)


@router.put("/v2/Users/{user_id}")
async def replace_user(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: ScimBearerToken = Depends(get_scim_client),
):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return _scim_error(400, "Invalid user ID format")

    scim_data = await request.json()
    base_url = _get_base_url(request)
    result = await scim_service.update_user(db, uid, scim_data, base_url)
    if result is None:
        return _scim_error(404, f"User {user_id} not found")
    return _scim_response(result)


@router.patch("/v2/Users/{user_id}")
async def patch_user(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: ScimBearerToken = Depends(get_scim_client),
):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return _scim_error(400, "Invalid user ID format")

    scim_data = await request.json()
    operations = scim_data.get("Operations", [])
    base_url = _get_base_url(request)
    result = await scim_service.patch_user(db, uid, operations, base_url)
    if result is None:
        return _scim_error(404, f"User {user_id} not found")
    return _scim_response(result)


@router.delete("/v2/Users/{user_id}")
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    token: ScimBearerToken = Depends(get_scim_client),
):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return _scim_error(400, "Invalid user ID format")

    success = await scim_service.delete_user(db, uid)
    if not success:
        return _scim_error(404, f"User {user_id} not found")
    return JSONResponse(content=None, status_code=204, media_type=SCIM_CONTENT_TYPE)


@router.get("/v2/ServiceProviderConfig")
async def service_provider_config(
    token: ScimBearerToken = Depends(get_scim_client),
):
    config = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/mcatsim/LexNebulis/wiki/SCIM",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token Standard",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
                "documentationUri": "https://github.com/mcatsim/LexNebulis/wiki/SCIM",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": "/api/scim/v2/ServiceProviderConfig",
        },
    }
    return _scim_response(config)


@router.get("/v2/ResourceTypes")
async def resource_types(
    token: ScimBearerToken = Depends(get_scim_client),
):
    resource_types = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            "schemaExtensions": [
                {
                    "schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                    "required": False,
                }
            ],
            "meta": {
                "resourceType": "ResourceType",
                "location": "/api/scim/v2/ResourceTypes/User",
            },
        }
    ]
    return _scim_response(resource_types)


@router.get("/v2/Schemas")
async def schemas(
    token: ScimBearerToken = Depends(get_scim_client),
):
    schema_list = [
        {
            "id": "urn:ietf:params:scim:schemas:core:2.0:User",
            "name": "User",
            "description": "User Account",
            "attributes": [
                {
                    "name": "userName",
                    "type": "string",
                    "multiValued": False,
                    "description": "Unique identifier for the User (email address)",
                    "required": True,
                    "caseExact": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "server",
                },
                {
                    "name": "name",
                    "type": "complex",
                    "multiValued": False,
                    "description": "Components of the user's name",
                    "required": False,
                    "subAttributes": [
                        {
                            "name": "givenName",
                            "type": "string",
                            "multiValued": False,
                            "required": False,
                            "mutability": "readWrite",
                            "returned": "default",
                        },
                        {
                            "name": "familyName",
                            "type": "string",
                            "multiValued": False,
                            "required": False,
                            "mutability": "readWrite",
                            "returned": "default",
                        },
                    ],
                },
                {
                    "name": "emails",
                    "type": "complex",
                    "multiValued": True,
                    "description": "Email addresses for the user",
                    "required": False,
                    "subAttributes": [
                        {"name": "value", "type": "string", "multiValued": False, "required": False},
                        {"name": "primary", "type": "boolean", "multiValued": False, "required": False},
                        {"name": "type", "type": "string", "multiValued": False, "required": False},
                    ],
                },
                {
                    "name": "active",
                    "type": "boolean",
                    "multiValued": False,
                    "description": "Indicates whether the user account is active",
                    "required": False,
                    "mutability": "readWrite",
                    "returned": "default",
                },
            ],
            "meta": {
                "resourceType": "Schema",
                "location": "/api/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
            },
        }
    ]
    return _scim_response(schema_list)
