"""Case queries and atomic mutation/audit transactions."""

from fastapi import HTTPException
from sqlalchemy import func, select

from godeep.persistence.models import AuditEvent, Case, Sample
from godeep.schemas.intake import CaseCreate


def require_case(session, case_id: str) -> Case:
    case = session.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    return case


def create_case(factory, payload: CaseCreate) -> Case:
    with factory.begin() as session:
        case = Case(**payload.model_dump())
        session.add(case)
        session.flush()
        session.add(
            AuditEvent(
                case_id=case.id,
                action="case.created",
                subject_id=case.id,
                details={"name": case.name},
            )
        )
    return case


def get_case(factory, case_id: str) -> Case:
    with factory() as session:
        return require_case(session, case_id)


def list_records(factory, model, limit: int, offset: int, case_id: str | None = None):
    with factory() as session:
        statement = select(model)
        count = select(func.count()).select_from(model)
        if case_id is not None:
            require_case(session, case_id)
            statement = statement.where(model.case_id == case_id)
            count = count.where(model.case_id == case_id)
        total = session.scalar(count)
        rows = session.scalars(
            statement.order_by(model.created_at.desc(), model.id).limit(limit).offset(offset)
        ).all()
        return {"items": rows, "total": total, "limit": limit, "offset": offset}


def get_sample(factory, case_id: str, sample_id: str) -> Sample:
    with factory() as session:
        require_case(session, case_id)
        sample = session.get(Sample, sample_id)
        if sample is None or sample.case_id != case_id:
            raise HTTPException(404, "Sample not found in this case")
        return sample
