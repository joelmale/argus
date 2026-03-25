"""add scanner ai control plane fields

Revision ID: 20260324_0027
Revises: 20260321_0026
Create Date: 2026-03-24 22:10:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260324_0027"
down_revision = "20260321_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scanner_configs", sa.Column("ai_backend", sa.String(length=16), nullable=False, server_default="ollama"))
    op.add_column("scanner_configs", sa.Column("ai_model", sa.String(length=128), nullable=True))
    op.add_column("scanner_configs", sa.Column("fingerprint_ai_backend", sa.String(length=16), nullable=False, server_default="ollama"))
    op.add_column("scanner_configs", sa.Column("ollama_base_url", sa.Text(), nullable=True))
    op.add_column("scanner_configs", sa.Column("openai_base_url", sa.Text(), nullable=True))
    op.add_column("scanner_configs", sa.Column("openai_api_key", sa.Text(), nullable=True))
    op.add_column("scanner_configs", sa.Column("anthropic_api_key", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("scanner_configs", "anthropic_api_key")
    op.drop_column("scanner_configs", "openai_api_key")
    op.drop_column("scanner_configs", "openai_base_url")
    op.drop_column("scanner_configs", "ollama_base_url")
    op.drop_column("scanner_configs", "fingerprint_ai_backend")
    op.drop_column("scanner_configs", "ai_model")
    op.drop_column("scanner_configs", "ai_backend")
