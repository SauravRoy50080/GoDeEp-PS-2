"""Append-only report reviews with atomic per-report allocation."""

import sqlalchemy as sa
from alembic import op

revision = "0006_report_reviews"
down_revision = "0005_runtime_captures"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "forensic_reports",
        sa.Column("review_entry_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "report_review_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("forensic_reports.id"), nullable=False),
        sa.Column(
            "thread_id", sa.String(36), sa.ForeignKey("report_review_entries.id"), nullable=False
        ),
        sa.Column("supersedes_id", sa.String(36), sa.ForeignKey("report_review_entries.id")),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("report_sha256", sa.String(64), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("evidence_references", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "decision IN ('comment','supported','disputed','follow_up')", name="ck_review_decision"
        ),
        sa.CheckConstraint(
            "(supersedes_id IS NULL AND thread_id = id) OR "
            "(supersedes_id IS NOT NULL AND thread_id <> id)",
            name="ck_review_thread",
        ),
        sa.UniqueConstraint("supersedes_id", name="uq_review_supersedes"),
    )
    op.create_index("ix_report_review_entries_report_id", "report_review_entries", ["report_id"])
    op.create_index("ix_report_review_entries_thread_id", "report_review_entries", ["thread_id"])


def downgrade():
    # Self-references prevent a direct DROP with live rows on SQLite.
    op.execute(sa.text("DELETE FROM report_review_entries"))
    op.drop_table("report_review_entries")
    op.drop_column("forensic_reports", "review_entry_count")
