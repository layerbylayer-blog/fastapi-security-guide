import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from app.auth.jwt import create_access_token, create_refresh_token, decode_token
from app.auth.revocation import revoke
from app.auth.dependencies import get_current_user
from app.repositories.user_repository import UserRepository, get_user_repo
from app.services.user_service import UserService
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class RegisterRequest(BaseModel):
    username: str
    password: str


def get_user_service(user_repo: UserRepository = Depends(get_user_repo)) -> UserService:
    return UserService(user_repo=user_repo)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    user_service: UserService = Depends(get_user_service),
):
    from app.repositories.user_repository import UserRepository
    user = await user_service.user_repo.get_by_username(body.username)
    if user:
        raise HTTPException(status_code=400, detail="Username already taken")
    new_user = await user_service.create_user(body.username, body.password)
    return {"id": str(new_user.id), "username": new_user.username}


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_service: UserService = Depends(get_user_service),
):
    user = await user_service.authenticate(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(
        access_token=create_access_token(subject=str(user.id)),
        refresh_token=create_refresh_token(subject=str(user.id)),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    user_repo: UserRepository = Depends(get_user_repo),
):
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload["sub"]
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Verify user still exists and is active — a valid token is not enough
    user = await user_repo.get(user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return TokenResponse(
        access_token=create_access_token(subject=user_id),
        refresh_token=create_refresh_token(subject=user_id),
    )


oauth2_scheme_local = OAuth2PasswordBearer(tokenUrl="/auth/login")


@router.post("/logout", status_code=204)
async def logout(
    token: str = Depends(oauth2_scheme_local),
    current_user: User = Depends(get_current_user),
):
    """Revoke the current access token by adding its jti to the blacklist."""
    payload = decode_token(token)
    jti = payload.get("jti")
    if jti:
        revoke(jti)
