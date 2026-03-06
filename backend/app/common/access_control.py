"""
Resource-level access control for LexNebulis.

Admins have full access. Other roles are scoped to matters they are
assigned to (as attorney) or have been granted access via matter teams
(future). Ethical-wall blocked matters are always denied.
"""

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User


async def check_matter_access(
    db: AsyncSession,
    user: User,
    matter_id: uuid.UUID,
) -> None:
    """Raise 403 if the user does not have access to the specified matter.

    Access rules:
    - admin: unrestricted
    - attorney/paralegal/billing_clerk: must be assigned_attorney or
      a member of the matter team
    - Ethical-wall blocked matters: always denied (checked via conflicts)
    """
    if user.role.value == "admin":
        return

    from app.matters.models import Matter

    result = await db.execute(select(Matter).where(Matter.id == matter_id))
    matter = result.scalar_one_or_none()
    if matter is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Matter not found",
        )

    # Check ethical walls first — always deny
    from app.conflicts.models import EthicalWall

    wall_result = await db.execute(
        select(EthicalWall).where(
            EthicalWall.matter_id == matter_id,
            EthicalWall.user_id == user.id,
        )
    )
    if wall_result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: ethical wall",
        )

    # Check if user is assigned attorney
    if matter.assigned_attorney_id == user.id:
        return

    # For non-admin users who are not the assigned attorney, deny access
    # Future: check matter_team membership table here
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You do not have access to this matter",
    )
