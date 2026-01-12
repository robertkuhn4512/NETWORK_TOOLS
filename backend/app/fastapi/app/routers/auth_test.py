from fastapi import APIRouter, Depends

from app.security.auth import UserContext, get_current_user, require_roles

router = APIRouter(prefix="/auth-test", tags=["auth-test"])

@router.get("/whoami")
def whoami(user: UserContext = Depends(get_current_user)):
    return {"detail": {"sub": user.sub, "username": user.username, "roles": user.roles, "azp": user.azp}}

@router.get("/admin-only")
def admin_only(user: UserContext = Depends(require_roles("admin"))):
    return {"detail": {"ok": True, "msg": "You have the admin role", "user": user.username}}
