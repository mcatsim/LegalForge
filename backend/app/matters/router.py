import json
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User
from app.auth.service import create_audit_log
from app.common.access_control import check_matter_access
from app.common.pagination import PaginatedResponse
from app.database import get_db
from app.dependencies import get_current_user, require_roles
from app.matters.models import LitigationType, MatterStatus
from app.matters.schemas import MatterContactAdd, MatterCreate, MatterResponse, MatterUpdate
from app.matters.service import (
    add_matter_contact,
    create_matter,
    delete_matter,
    get_matter,
    get_matters,
    remove_matter_contact,
    update_matter,
)

router = APIRouter()


@router.get("", response_model=PaginatedResponse)
async def list_matters(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    page: int = 1,
    page_size: int = 25,
    search: Optional[str] = None,
    status: Optional[MatterStatus] = None,
    client_id: Optional[uuid.UUID] = None,
    attorney_id: Optional[uuid.UUID] = None,
    litigation_type: Optional[LitigationType] = None,
):
    # Non-admin users can only see matters they are assigned to
    if current_user.role.value != "admin":
        attorney_id = current_user.id
    matters, total = await get_matters(db, page, page_size, search, status, client_id, attorney_id, litigation_type)
    items = [MatterResponse.model_validate(m).model_dump() for m in matters]
    return PaginatedResponse.create(items=items, total=total, page=page, page_size=page_size)


@router.get("/{matter_id}", response_model=MatterResponse)
async def get_matter_detail(
    matter_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    await check_matter_access(db, current_user, matter_id)
    matter = await get_matter(db, matter_id)
    if matter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Matter not found")
    return matter


@router.post("", response_model=MatterResponse, status_code=status.HTTP_201_CREATED)
async def create_new_matter(
    data: MatterCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_roles("admin", "attorney", "paralegal"))],
):
    matter = await create_matter(db, data)
    await create_audit_log(
        db,
        current_user.id,
        "matter",
        str(matter.id),
        "create",
        changes_json=json.dumps(data.model_dump(), default=str),
        ip_address=request.client.host if request.client else None,
    )
    return matter


@router.put("/{matter_id}", response_model=MatterResponse)
async def update_existing_matter(
    matter_id: uuid.UUID,
    data: MatterUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_roles("admin", "attorney", "paralegal"))],
):
    await check_matter_access(db, current_user, matter_id)
    matter = await get_matter(db, matter_id)
    if matter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Matter not found")

    updated = await update_matter(db, matter, data)
    await create_audit_log(
        db,
        current_user.id,
        "matter",
        str(matter_id),
        "update",
        changes_json=json.dumps(data.model_dump(exclude_unset=True), default=str),
        ip_address=request.client.host if request.client else None,
    )
    return updated


@router.delete("/{matter_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_existing_matter(
    matter_id: uuid.UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_roles("admin"))],
):
    matter = await get_matter(db, matter_id)
    if matter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Matter not found")

    await delete_matter(db, matter)
    await create_audit_log(
        db,
        current_user.id,
        "matter",
        str(matter_id),
        "delete",
        ip_address=request.client.host if request.client else None,
    )


@router.post("/{matter_id}/contacts", status_code=status.HTTP_201_CREATED)
async def add_contact_to_matter(
    matter_id: uuid.UUID,
    data: MatterContactAdd,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_roles("admin", "attorney", "paralegal"))],
):
    await check_matter_access(db, current_user, matter_id)
    matter = await get_matter(db, matter_id)
    if matter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Matter not found")

    mc = await add_matter_contact(db, matter_id, data.contact_id, data.relationship_type)
    return {"id": str(mc.id), "contact_id": str(data.contact_id), "relationship_type": data.relationship_type}


@router.delete("/{matter_id}/contacts/{matter_contact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_contact_from_matter(
    matter_id: uuid.UUID,
    matter_contact_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_roles("admin", "attorney", "paralegal"))],
):
    await check_matter_access(db, current_user, matter_id)
    await remove_matter_contact(db, matter_contact_id)
