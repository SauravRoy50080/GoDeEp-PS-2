"""Persist case-scoped, hash-linked forensic report snapshots."""

import sqlalchemy as sa
from alembic import op

revision = "0004_forensic_reports"
down_revision = "0003_analysis_jobs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "forensic_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("sample_id", sa.String(36), sa.ForeignKey("samples.id"), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("source_job_ids", sa.JSON(), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("artifact_key", sa.String(80), nullable=False, unique=True),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("size_bytes > 0", name="ck_report_size"),
    )
    op.create_index("ix_forensic_reports_case_id", "forensic_reports", ["case_id"])
    op.create_index("ix_forensic_reports_sample_id", "forensic_reports", ["sample_id"])


def downgrade():
    op.drop_table("forensic_reports")
