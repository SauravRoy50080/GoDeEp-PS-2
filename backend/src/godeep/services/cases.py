"""Case-scoped access checks and atomic mutation/audit transactions."""

from fastapi import HTTPException
from sqlalchemy import exists, func, or_, select

from godeep.persistence.models import AuditEvent, Case, CaseMember, Sample, User
from godeep.schemas.auth import MemberWrite
from godeep.schemas.intake import CaseCreate


def require_case(session, case_id: str, user_id: str, *, write=False, manage=False) -> Case:
    case = session.get(Case, case_id)
    membership = session.get(CaseMember, (case_id, user_id)) if case is not None else None
    owner = case is not None and case.owner_id == user_id
    if case is None or (not owner and membership is None):
        raise HTTPException(404, "Case not found")
    if (manage and not owner) or (write and not owner and membership.role != "analyst"):
        raise HTTPException(403, "Insufficient case permissions")
    return case


def create_case(factory, payload: CaseCreate, user_id: str) -> Case:
    with factory.begin() as session:
        case = Case(**payload.model_dump(), owner_id=user_id)
        session.add(case)
        session.flush()
        session.add(
            AuditEvent(
                case_id=case.id,
                action="case.created",
                actor=user_id,
                subject_id=case.id,
                details={"name": case.name},
            )
        )
    return case


def get_case(factory, case_id: str, user_id: str, *, write=False) -> Case:
    with factory() as session:
        return require_case(session, case_id, user_id, write=write)


def list_records(factory, model, limit: int, offset: int, user_id: str, case_id: str | None = None):
    with factory() as session:
        statement = select(model)
        count = select(func.count()).select_from(model)
        if case_id is not None:
            require_case(session, case_id, user_id)
            predicate = model.case_id == case_id
        else:
            predicate = or_(
                Case.owner_id == user_id,
                exists().where(CaseMember.case_id == Case.id, CaseMember.user_id == user_id),
            )
        total = session.scalar(count.where(predicate))
        rows = session.scalars(
            statement.where(predicate)
            .order_by(model.created_at.desc(), model.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return {"items": rows, "total": total, "limit": limit, "offset": offset}


def get_sample(factory, case_id: str, sample_id: str, user_id: str) -> Sample:
    with factory() as session:
        require_case(session, case_id, user_id)
        sample = session.get(Sample, sample_id)
        if sample is None or sample.case_id != case_id:
            raise HTTPException(404, "Sample not found in this case")
        return sample


def set_member(factory, case_id: str, actor_id: str, payload: MemberWrite):
    with factory.begin() as session:
        case = require_case(session, case_id, actor_id, manage=True)
        target_id = str(payload.user_id)
        target = session.get(User, target_id)
        if target is None or not target.is_active:
            raise HTTPException(404, "Active user not found")
        if target_id == case.owner_id:
            raise HTTPException(409, "Owner permissions cannot be changed through membership")
        membership = session.get(CaseMember, (case_id, target_id))
        if membership is None:
            membership = CaseMember(case_id=case_id, user_id=target_id, role=payload.role)
            session.add(membership)
        else:
            membership.role = payload.role
        session.add(
            AuditEvent(
                case_id=case_id,
                action="case.member_set",
                actor=actor_id,
                subject_id=target_id,
                details={"role": payload.role},
            )
        )
    return membership


def list_members(factory, case_id: str, actor_id: str):
    with factory() as session:
        require_case(session, case_id, actor_id, manage=True)
        return session.scalars(
            select(CaseMember).where(CaseMember.case_id == case_id).order_by(CaseMember.user_id)
        ).all()


def remove_member(factory, case_id: str, actor_id: str, user_id: str):
    with factory.begin() as session:
        case = require_case(session, case_id, actor_id, manage=True)
        if user_id == case.owner_id:
            raise HTTPException(409, "Owner cannot be removed through membership")
        membership = session.get(CaseMember, (case_id, user_id))
        if membership is None:
            raise HTTPException(404, "Membership not found")
        session.delete(membership)
        session.add(
            AuditEvent(
                case_id=case_id,
                action="case.member_removed",
                actor=actor_id,
                subject_id=user_id,
                details={},
            )
        )


def claim_legacy_case(factory, case_id: str, username: str):
    with factory.begin() as session:
        case = session.scalar(select(Case).where(Case.id == case_id).with_for_update())
        user = session.scalar(select(User).where(User.username == username.lower()))
        if case is None or user is None or not user.is_active:
            raise ValueError("Case or active user not found")
        if case.owner_id is not None:
            raise ValueError("Case already has an owner")
        case.owner_id = user.id
        session.add(
            AuditEvent(
                case_id=case_id,
                action="case.legacy_assigned",
                actor="operator-cli",
                subject_id=user.id,
                details={"owner_id": user.id},
            )
        )
