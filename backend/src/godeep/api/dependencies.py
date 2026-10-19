"""A verified principal is required for every investigation operation."""

from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from godeep.schemas.auth import Principal
from godeep.services.auth import authenticate, unauthorized

bearer = HTTPBearer(
    auto_error=False, description="Opaque session token from POST /api/v1/auth/login"
)


def current_principal(
    request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized()
    return authenticate(request.app.state.sessions, credentials.credentials)


CurrentUser = Annotated[Principal, Depends(current_principal)]
