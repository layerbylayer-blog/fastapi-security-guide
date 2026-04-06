from fastapi import APIRouter, Depends
from app.auth.dependencies import get_current_active_user
from app.models import User

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me")
async def get_profile(current_user: User = Depends(get_current_active_user)):
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "is_active": current_user.is_active,
    }
