from app.auth.password import hash_password, verify_password
from app.repositories.user_repository import UserRepository
from app.models import User

# Dummy hash used for timing-safe authentication when user doesn't exist
_DUMMY_HASH = "$2b$12$Wp815XjnQdZOIJZqaJioruc3qYeViENIrNKTLUInB.s.xz0F58Mdq"


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create_user(self, username: str, password: str) -> User:
        hashed = hash_password(password)
        return await self.user_repo.create(username=username, hashed_password=hashed)

    async def authenticate(self, username: str, password: str) -> User | None:
        user = await self.user_repo.get_by_username(username)
        if user is None:
            # Timing attack mitigation: always run verify even if user not found
            verify_password("dummy", _DUMMY_HASH)
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user


def get_user_service(user_repo: UserRepository = None) -> UserService:
    from fastapi import Depends
    from app.repositories.user_repository import get_user_repo

    def _get(repo: UserRepository = Depends(get_user_repo)) -> UserService:
        return UserService(user_repo=repo)

    return _get
