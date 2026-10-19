"""Add users, revocable sessions and case membership; legacy cases stay unowned."""

import sqlalchemy as sa
from alembic import op

revision = "0002_auth"
down_revision = "0001_intake"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(80), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column("cases", sa.Column("owner_id", sa.String(36), nullable=True))
    with op.batch_alter_table("cases") as batch:
        batch.create_foreign_key("fk_cases_owner_id_users", "users", ["owner_id"], ["id"])
        batch.create_index("ix_cases_owner_id", ["owner_id"])
    op.create_table(
        "auth_sessions",
        sa.Column("token_digest", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_table(
        "case_members",
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.id"), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("role", sa.String(20), nullable=False),
        sa.CheckConstraint("role IN ('analyst', 'viewer')", name="ck_member_role"),
    )


def downgrade():
    op.drop_table("case_members")
    op.drop_table("auth_sessions")
    with op.batch_alter_table("cases") as batch:
        batch.drop_index("ix_cases_owner_id")
        batch.drop_constraint("fk_cases_owner_id_users", type_="foreignkey")
        batch.drop_column("owner_id")
    op.drop_table("users")
