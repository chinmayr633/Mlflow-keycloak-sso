"""Add a display name for externally managed users.

Revision ID: b4c17a0e3d92
Revises: f1a2b3c4d5e6
"""

import sqlalchemy as sa
from alembic import op

revision = "b4c17a0e3d92"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("display_name", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "display_name")
