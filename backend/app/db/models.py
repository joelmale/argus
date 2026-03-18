"""
Core data models for Argus.

Entity relationships (simplified graph):
  User ──< ScanJob >── [discovers] ──> Asset
  Asset ──< Port
  Asset ──< AssetTag
  Asset ──< AssetHistory  (change log)
  Asset ──> Asset          (topology: network links, adjacency list)
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(256), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(256))
    vendor: Mapped[str | None] = mapped_column(String(256))        # MAC OUI lookup
    os_name: Mapped[str | None] = mapped_column(String(256))
    os_version: Mapped[str | None] = mapped_column(String(128))
    device_type: Mapped[str | None] = mapped_column(String(64))    # router, switch, server, etc.
    status: Mapped[str] = mapped_column(String(16), default="online")  # online | offline | unknown
    notes: Mapped[str | None] = mapped_column(Text)
    custom_fields: Mapped[dict | None] = mapped_column(JSONB)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    ports: Mapped[list["Port"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    tags: Mapped[list["AssetTag"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    history: Mapped[list["AssetHistory"]] = relationship(back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("ip_address", name="uq_asset_ip"),)


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"))
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(4), default="tcp")   # tcp | udp
    service: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(16), default="open")

    asset: Mapped["Asset"] = relationship(back_populates="ports")

    __table_args__ = (UniqueConstraint("asset_id", "port_number", "protocol", name="uq_port"),)


class AssetTag(Base):
    __tablename__ = "asset_tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"))
    tag: Mapped[str] = mapped_column(String(64), nullable=False)

    asset: Mapped["Asset"] = relationship(back_populates="tags")


class AssetHistory(Base):
    """Immutable change log for an asset — append-only audit trail."""
    __tablename__ = "asset_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    change_type: Mapped[str] = mapped_column(String(32))  # discovered | port_changed | os_changed | offline | online
    diff: Mapped[dict | None] = mapped_column(JSONB)      # {field: {old, new}}

    asset: Mapped["Asset"] = relationship(back_populates="history")


class TopologyLink(Base):
    """Directed adjacency list for network topology graph."""
    __tablename__ = "topology_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"))
    link_type: Mapped[str] = mapped_column(String(32), default="ethernet")  # ethernet | wifi | vlan | vpn
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    link_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB)

    __table_args__ = (UniqueConstraint("source_id", "target_id", name="uq_topology_link"),)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    targets: Mapped[str] = mapped_column(Text, nullable=False)  # CIDR or IP list
    scan_type: Mapped[str] = mapped_column(String(32), default="full")  # full | quick | ports | snmp
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | running | done | failed
    triggered_by: Mapped[str] = mapped_column(String(32), default="schedule")  # schedule | manual | api
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_summary: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    hashed_key: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="api_keys")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User | None] = relationship(back_populates="audit_logs")


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(256))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_webhook: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConfigBackupTarget(Base):
    __tablename__ = "config_backup_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    driver: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    password_env_var: Mapped[str | None] = mapped_column(String(128))
    port: Mapped[int] = mapped_column(Integer, default=22)
    host_override: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ConfigBackupSnapshot(Base):
    __tablename__ = "config_backup_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    target_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("config_backup_targets.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    driver: Mapped[str] = mapped_column(String(64), nullable=False)
    command: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WirelessAssociation(Base):
    __tablename__ = "wireless_associations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_point_asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    client_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"))
    client_mac: Mapped[str | None] = mapped_column(String(17))
    client_ip: Mapped[str | None] = mapped_column(String(45))
    ssid: Mapped[str | None] = mapped_column(String(128))
    band: Mapped[str | None] = mapped_column(String(32))
    signal_dbm: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32), default="snmp")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    port_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("ports.id", ondelete="SET NULL"))
    source_tool: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    status: Mapped[str] = mapped_column(String(16), default="open")
    cve: Mapped[str | None] = mapped_column(String(64))
    service: Mapped[str | None] = mapped_column(String(64))
    port_number: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(8))
    finding_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ConfigBackupPolicy(Base):
    __tablename__ = "config_backup_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=720)
    tag_filter: Mapped[str] = mapped_column(String(64), default="infrastructure")
    retention_count: Mapped[int] = mapped_column(Integer, default=5)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ScannerConfig(Base):
    __tablename__ = "scanner_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    default_targets: Mapped[str | None] = mapped_column(Text)
    auto_detect_targets: Mapped[bool] = mapped_column(Boolean, default=True)
    default_profile: Mapped[str] = mapped_column(String(32), default="balanced")
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    concurrent_hosts: Mapped[int] = mapped_column(Integer, default=10)
    last_scheduled_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
