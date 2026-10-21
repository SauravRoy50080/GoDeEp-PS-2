"""Query contracts for read-only report runtime review views."""

from typing import Literal
from uuid import UUID

from fastapi import Query

InventorySection = Literal["process", "filesystem", "network", "sensitive_access"]
ReviewSection = Literal["process", "filesystem", "network", "sensitive_access", "activity"]


class ReviewQuery:
    def __init__(
        self,
        section: ReviewSection = Query("process"),
        capture_id: UUID | None = Query(None),
        bucket_seconds: int = Query(10, ge=1, le=3600),
        limit: int = Query(100, ge=1, le=200),
        offset: int = Query(0, ge=0, le=40000),
    ):
        self.values = {
            "section": section,
            "capture_id": str(capture_id) if capture_id else None,
            "bucket_seconds": bucket_seconds,
            "limit": limit,
            "offset": offset,
        }


class ComparisonQuery:
    def __init__(
        self,
        left_capture_id: UUID = Query(...),
        right_capture_id: UUID = Query(...),
        section: InventorySection = Query("process"),
        limit: int = Query(100, ge=1, le=200),
        offset: int = Query(0, ge=0, le=40000),
    ):
        self.values = {
            "section": section,
            "left": str(left_capture_id),
            "right": str(right_capture_id),
            "limit": limit,
            "offset": offset,
        }
