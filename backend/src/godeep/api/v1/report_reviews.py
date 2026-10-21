"""Case-authorized append-only analyst review and passive evidence-linked exports."""

import json
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from godeep.api.dependencies import CurrentUser
from godeep.schemas.report_reviews import ReviewCreate, ReviewRead
from godeep.services import report_reviews
from godeep.services.report_html import CSP

router = APIRouter(
    prefix="/cases/{case_id}/samples/{sample_id}/reports/{report_id}/reviews",
    tags=["analyst reviews"],
)


def response(raw, *, html=False):
    data = json.loads(raw) if not html else None
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Export-SHA256": report_reviews.digest(raw),
        "X-Review-Version": report_reviews.VERSION,
    }
    if data:
        headers["X-Source-Report-SHA256"] = data["source_report_sha256"]
    if html:
        headers.update(
            {
                "Content-Security-Policy": CSP,
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            }
        )
    return Response(raw, media_type="text/html" if html else "application/json", headers=headers)


@router.post("", response_model=ReviewRead, status_code=201)
def create(
    case_id: UUID,
    sample_id: UUID,
    report_id: UUID,
    payload: ReviewCreate,
    request: Request,
    user: CurrentUser,
):
    return report_reviews.create(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
        payload,
    )


@router.get("", response_class=Response)
def listing(
    case_id: UUID,
    sample_id: UUID,
    report_id: UUID,
    request: Request,
    user: CurrentUser,
    current: bool = False,
    thread_id: UUID | None = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0, le=2000),
):
    raw = report_reviews.listing(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
        current=current,
        thread_id=str(thread_id) if thread_id else None,
        limit=limit,
        offset=offset,
    )
    return response(raw)


@router.get("/export/json", response_class=Response)
def json_export(
    case_id: UUID, sample_id: UUID, report_id: UUID, request: Request, user: CurrentUser
):
    raw = report_reviews.export(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
    )
    result = response(raw)
    result.headers["Content-Disposition"] = 'attachment; filename="godeep-analyst-reviews.json"'
    return result


@router.get("/export/html", response_class=Response)
def html_export(
    case_id: UUID, sample_id: UUID, report_id: UUID, request: Request, user: CurrentUser
):
    raw = report_reviews.export(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(report_id),
        user.user_id,
    )
    result = response(
        report_reviews.render(raw, request.app.state.settings.max_report_review_html_bytes),
        html=True,
    )
    result.headers["X-Source-Report-SHA256"] = json.loads(raw)["source_report_sha256"]
    result.headers["Content-Disposition"] = 'attachment; filename="godeep-analyst-reviews.html"'
    return result
