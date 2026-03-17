"""add user roles

Revision ID: 202603170002
Revises: 202603170001
Create Date: 2026-03-17 13:05:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "202603170002"
down_revision = "202603170001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("role", sa.String(length=16), nullable=True))
    op.execute("UPDATE users SET role = CASE WHEN is_admin THEN 'admin' ELSE 'viewer' END")
    op.alter_column("users", "role", nullable=False)
    op.drop_column("users", "is_admin")


def downgrade() -> None:
    op.add_column("users", sa.Column("is_admin", sa.Boolean(), nullable=True))
    op.execute("UPDATE users SET is_admin = CASE WHEN role = 'admin' THEN TRUE ELSE FALSE END")
    op.alter_column("users", "is_admin", nullable=False)
    op.drop_column("users", "role")
