"""Authenticated report creation, metadata and verified JSON/HTML downloads."""

import hashlib
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from godeep.api.dependencies import CurrentUser
from godeep.schemas.intake import Page
from godeep.schemas.reports import ReportCreate, ReportRead
from godeep.services import report_html, reports
from godeep.services.network_correlation import network_correlation

router = APIRouter(prefix="/cases/{case_id}/samples/{sample_id}/reports", tags=["forensic reports"])


@router.get("/{report_id}/export/html", response_class=Response)
def html_export(
    case_id: UUID, sample_id: UUID, report_id: UUID, request: Request, user: CurrentUser
):
    report, raw = reports.download_report(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
    )
    rendered = report_html.render(raw, report, request.app.state.settings.max_report_html_bytes)
    return Response(
        rendered,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="godeep-report-{report.id}.html"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": report_html.CSP,
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "X-Source-Report-SHA256": report.artifact_sha256,
            "X-Export-SHA256": hashlib.sha256(rendered).hexdigest(),
            "X-Export-Version": report_html.EXPORT_VERSION,
        },
    )


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


@router.get("/{report_id}/network-correlation", response_class=Response)
def correlate_network(
    case_id: UUID,
    sample_id: UUID,
    report_id: UUID,
    request: Request,
    user: CurrentUser,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0, le=20000),
):
    raw = network_correlation(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
        limit,
        offset,
    )
    return Response(
        raw,
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
