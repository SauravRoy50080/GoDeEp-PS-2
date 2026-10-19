"""Only case owners may manage memberships."""

from uuid import UUID

from fastapi import APIRouter, Request

from godeep.api.dependencies import CurrentUser
from godeep.schemas.auth import MemberRead, MemberWrite
from godeep.services import cases

router = APIRouter(prefix="/cases/{case_id}/members", tags=["case permissions"])


@router.get("", response_model=list[MemberRead])
def list_members(case_id: UUID, user: CurrentUser, request: Request):
    return cases.list_members(request.app.state.sessions, str(case_id), user.user_id)


@router.put("", response_model=MemberRead)
def set_member(case_id: UUID, payload: MemberWrite, user: CurrentUser, request: Request):
    return cases.set_member(request.app.state.sessions, str(case_id), user.user_id, payload)


@router.delete("/{user_id}", status_code=204)
def remove_member(case_id: UUID, user_id: UUID, user: CurrentUser, request: Request):
    cases.remove_member(request.app.state.sessions, str(case_id), user.user_id, str(user_id))
