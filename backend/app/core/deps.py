from typing import Annotated
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.auth import decode_token, CREDENTIALS_EXCEPTION
from app.db.session import AsyncSessionLocal
from app.models import User, UserRole

bearer_scheme = HTTPBearer(auto_error=False)


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


DbDep = Annotated[AsyncSession, Depends(get_db)]


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: DbDep,
) -> User:
    if not credentials:
        raise CREDENTIALS_EXCEPTION

    payload = decode_token(credentials.credentials)
    user_id: str | None = payload.get("sub")
    if user_id is None:
        raise CREDENTIALS_EXCEPTION

    from sqlalchemy import select
    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if user is None:
        raise CREDENTIALS_EXCEPTION

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: UserRole):
    async def _check(current_user: CurrentUser) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {[r.value for r in roles]}",
            )
        return current_user
    return _check


def require_admin():
    return require_roles(UserRole.ADMIN)


def require_analyst():
    return require_roles(UserRole.ADMIN, UserRole.ANALYST)
