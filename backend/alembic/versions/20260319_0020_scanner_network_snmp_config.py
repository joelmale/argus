"""add scanner network and snmp config

Revision ID: 20260319_0020
Revises: 20260318_0019
Create Date: 2026-03-19 00:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260319_0020"
down_revision = "20260318_0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scanner_configs", sa.Column("passive_arp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("scanner_configs", sa.Column("passive_arp_interface", sa.String(length=64), nullable=False, server_default="eth0"))
    op.add_column("scanner_configs", sa.Column("snmp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("scanner_configs", sa.Column("snmp_version", sa.String(length=8), nullable=False, server_default="2c"))
    op.add_column("scanner_configs", sa.Column("snmp_community", sa.String(length=128), nullable=False, server_default="public"))
    op.add_column("scanner_configs", sa.Column("snmp_timeout", sa.Integer(), nullable=False, server_default="5"))
    op.add_column("scanner_configs", sa.Column("snmp_v3_username", sa.String(length=128), nullable=True))
    op.add_column("scanner_configs", sa.Column("snmp_v3_auth_key", sa.String(length=256), nullable=True))
    op.add_column("scanner_configs", sa.Column("snmp_v3_priv_key", sa.String(length=256), nullable=True))
    op.add_column("scanner_configs", sa.Column("snmp_v3_auth_protocol", sa.String(length=16), nullable=False, server_default="sha"))
    op.add_column("scanner_configs", sa.Column("snmp_v3_priv_protocol", sa.String(length=16), nullable=False, server_default="aes"))


def downgrade() -> None:
    op.drop_column("scanner_configs", "snmp_v3_priv_protocol")
    op.drop_column("scanner_configs", "snmp_v3_auth_protocol")
    op.drop_column("scanner_configs", "snmp_v3_priv_key")
    op.drop_column("scanner_configs", "snmp_v3_auth_key")
    op.drop_column("scanner_configs", "snmp_v3_username")
    op.drop_column("scanner_configs", "snmp_timeout")
    op.drop_column("scanner_configs", "snmp_community")
    op.drop_column("scanner_configs", "snmp_version")
    op.drop_column("scanner_configs", "snmp_enabled")
    op.drop_column("scanner_configs", "passive_arp_interface")
    op.drop_column("scanner_configs", "passive_arp_enabled")
