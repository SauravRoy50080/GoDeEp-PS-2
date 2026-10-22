"""Authenticated report creation, metadata and verified JSON/HTML downloads."""

import hashlib
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from godeep.api.dependencies import CurrentUser
from godeep.reporting import evidence_package
from godeep.schemas.intake import Page
from godeep.schemas.reports import ReportCreate, ReportRead
from godeep.schemas.runtime_review import ComparisonQuery, ReviewQuery
from godeep.services import report_html, report_reviews, reports, runtime_review
from godeep.services.network_correlation import network_correlation

router = APIRouter(prefix="/cases/{case_id}/samples/{sample_id}/reports", tags=["forensic reports"])


@router.get("/{report_id}/export/package", response_class=Response)
def package_export(
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
    reviews = report_reviews.export(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
    )
    try:
        content = evidence_package.build(raw, reviews)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        from fastapi import HTTPException

        raise HTTPException(
            409, "Report and review snapshot cannot form an evidence package"
        ) from exc
    return Response(
        content,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="godeep-evidence-package.zip"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Source-Report-SHA256": report.artifact_sha256,
            "X-Export-SHA256": evidence_package.digest(content),
            "X-Export-Version": evidence_package.VERSION,
        },
    )


def runtime_view(case_id, sample_id, report_id, request, user, query, *, html=False):
    settings = request.app.state.settings
    raw = runtime_review.review(
        request.app.state.sessions,
        settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
        **query.values,
    )
    data = json.loads(raw)
    content = runtime_review.render(raw, settings.max_runtime_review_html_bytes) if html else raw
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Source-Report-SHA256": data["source_report_sha256"],
        "X-Export-SHA256": hashlib.sha256(content).hexdigest(),
        "X-Export-Version": runtime_review.VERSION,
        "Content-Disposition": 'attachment; filename="godeep-runtime-review.'
        + ("html" if html else "json")
        + '"',
    }
    if html:
        headers.update(
            {
                "Content-Security-Policy": report_html.CSP,
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            }
        )
    return Response(
        content, media_type="text/html" if html else "application/json", headers=headers
    )


@router.get("/{report_id}/runtime-review", response_class=Response)
def review_runtime(
    case_id: UUID,
    sample_id: UUID,
    report_id: UUID,
    request: Request,
    user: CurrentUser,
    query: Annotated[ReviewQuery, Depends()],
):
    """Paginated inventory or sparse elapsed activity buckets from selected report captures."""
    return runtime_view(case_id, sample_id, report_id, request, user, query)


@router.get("/{report_id}/runtime-review/export/html", response_class=Response)
def export_runtime_review(
    case_id: UUID,
    sample_id: UUID,
    report_id: UUID,
    request: Request,
    user: CurrentUser,
    query: Annotated[ReviewQuery, Depends()],
):
    """Printable selected page; the same filters, bounds and coverage as JSON."""
    return runtime_view(case_id, sample_id, report_id, request, user, query, html=True)


@router.get("/{report_id}/runtime-comparison", response_class=Response)
def compare_runtime(
    case_id: UUID,
    sample_id: UUID,
    report_id: UUID,
    request: Request,
    user: CurrentUser,
    query: Annotated[ComparisonQuery, Depends()],
):
    """Exact inventory identities in two distinct captures selected in this report."""
    return runtime_view(case_id, sample_id, report_id, request, user, query)


@router.get("/{report_id}/runtime-comparison/export/html", response_class=Response)
def export_runtime_comparison(
    case_id: UUID,
    sample_id: UUID,
    report_id: UUID,
    request: Request,
    user: CurrentUser,
    query: Annotated[ComparisonQuery, Depends()],
):
    return runtime_view(case_id, sample_id, report_id, request, user, query, html=True)


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
