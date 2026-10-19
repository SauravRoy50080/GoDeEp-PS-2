"""Login, current identity and current-session logout; no public registration."""

from fastapi import APIRouter, Request, Response

from godeep.api.dependencies import CurrentUser
from godeep.schemas.auth import LoginRequest, TokenRead, UserRead
from godeep.services import auth

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=TokenRead)
def login(payload: LoginRequest, request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return auth.login(
        request.app.state.sessions,
        request.app.state.settings,
        payload.username,
        payload.password.get_secret_value(),
    )


@router.get("/me", response_model=UserRead)
def me(user: CurrentUser, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return {"id": user.user_id, "username": user.username}


@router.post("/logout", status_code=204)
def logout(user: CurrentUser, request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    auth.logout(request.app.state.sessions, user)
