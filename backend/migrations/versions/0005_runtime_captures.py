"""Case-scoped imported runtime observation captures.

Revision ID: 0005_runtime_captures
Revises: 0004_forensic_reports
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_runtime_captures"
down_revision = "0004_forensic_reports"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "runtime_captures",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("sample_id", sa.String(36), sa.ForeignKey("samples.id"), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("source_run_id", sa.String(200), nullable=False),
        sa.Column("artifact_key", sa.String(100), nullable=False, unique=True),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("size_bytes > 0", name="ck_capture_size"),
        sa.UniqueConstraint("sample_id", "artifact_sha256", name="uq_capture_sample_artifact"),
    )
    op.create_index("ix_runtime_captures_case_id", "runtime_captures", ["case_id"])
    op.create_index("ix_runtime_captures_sample_id", "runtime_captures", ["sample_id"])


def downgrade():
    op.drop_index("ix_runtime_captures_sample_id", table_name="runtime_captures")
    op.drop_index("ix_runtime_captures_case_id", table_name="runtime_captures")
    op.drop_table("runtime_captures")
