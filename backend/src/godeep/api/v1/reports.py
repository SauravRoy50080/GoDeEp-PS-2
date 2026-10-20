"""Authenticated sample report creation, metadata and verified JSON downloads."""

from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from godeep.api.dependencies import CurrentUser
from godeep.schemas.intake import Page
from godeep.schemas.reports import ReportCreate, ReportRead
from godeep.services import reports

router = APIRouter(prefix="/cases/{case_id}/samples/{sample_id}/reports", tags=["forensic reports"])


@router.post("", response_model=ReportRead, status_code=201)
def create(
    case_id: UUID, sample_id: UUID, payload: ReportCreate, request: Request, user: CurrentUser
):
    return reports.create_report(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        user.user_id,
        payload.job_ids,
        payload.capture_ids,
    )


@router.get("", response_model=Page[ReportRead])
def listing(
    case_id: UUID,
    sample_id: UUID,
    request: Request,
    user: CurrentUser,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return reports.list_reports(
        request.app.state.sessions, str(case_id), str(sample_id), user.user_id, limit, offset
    )


@router.get("/{report_id}", response_model=ReportRead)
def metadata(case_id: UUID, sample_id: UUID, report_id: UUID, request: Request, user: CurrentUser):
    return reports.get_report(
        request.app.state.sessions, str(case_id), str(sample_id), str(report_id), user.user_id
    )


@router.get("/{report_id}/download", response_class=Response)
def download(case_id: UUID, sample_id: UUID, report_id: UUID, request: Request, user: CurrentUser):
    report, raw = reports.download_report(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
    )
    return Response(
        raw,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="godeep-report-{report.id}.json"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Report-SHA256": report.artifact_sha256,
        },
    )
