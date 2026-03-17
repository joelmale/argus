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
