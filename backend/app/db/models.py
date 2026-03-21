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

CASCADING_CHILDREN = "all, delete-orphan"
ASSET_ID_FK = "assets.id"
SET_NULL = "SET NULL"

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
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="user", cascade=CASCADING_CHILDREN)
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
    device_type: Mapped[str | None] = mapped_column(String(64))    # detected type from scanner/AI
    device_type_override: Mapped[str | None] = mapped_column(String(64))
    device_type_source: Mapped[str] = mapped_column(String(16), default="unknown")
    status: Mapped[str] = mapped_column(String(16), default="online")  # online | offline | unknown
    notes: Mapped[str | None] = mapped_column(Text)
    custom_fields: Mapped[dict | None] = mapped_column(JSONB)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    ports: Mapped[list["Port"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    tags: Mapped[list["AssetTag"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    history: Mapped[list["AssetHistory"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    ai_analysis: Mapped["AssetAIAnalysis | None"] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    evidence: Mapped[list["AssetEvidence"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    probe_runs: Mapped[list["ProbeRun"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    observations: Mapped[list["PassiveObservation"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    fingerprint_hypotheses: Mapped[list["FingerprintHypothesis"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    internet_lookup_results: Mapped[list["InternetLookupResult"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    lifecycle_records: Mapped[list["LifecycleRecord"]] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)
    autopsy: Mapped["AssetAutopsy | None"] = relationship(back_populates="asset", cascade=CASCADING_CHILDREN)

    __table_args__ = (UniqueConstraint("ip_address", name="uq_asset_ip"),)

    @property
    def effective_device_type(self) -> str:
        return self.device_type_override or self.device_type or "unknown"

    @property
    def effective_device_type_source(self) -> str:
        if self.device_type_override:
            return "manual"
        if self.device_type:
            return self.device_type_source or "detected"
        return "unknown"


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"))
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
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"))
    tag: Mapped[str] = mapped_column(String(64), nullable=False)

    asset: Mapped["Asset"] = relationship(back_populates="tags")


class AssetHistory(Base):
    """Immutable change log for an asset — append-only audit trail."""
    __tablename__ = "asset_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    change_type: Mapped[str] = mapped_column(String(32))  # discovered | port_changed | os_changed | offline | online
    diff: Mapped[dict | None] = mapped_column(JSONB)      # {field: {old, new}}

    asset: Mapped["Asset"] = relationship(back_populates="history")


class AssetAIAnalysis(Base):
    __tablename__ = "asset_ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(ASSET_ID_FK, ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    device_class: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[float] = mapped_column()
    vendor: Mapped[str | None] = mapped_column(String(256))
    model: Mapped[str | None] = mapped_column(String(256))
    os_guess: Mapped[str | None] = mapped_column(String(256))
    device_role: Mapped[str | None] = mapped_column(String(256))
    open_services_summary: Mapped[list | None] = mapped_column(JSONB)
    security_findings: Mapped[list | None] = mapped_column(JSONB)
    investigation_notes: Mapped[str | None] = mapped_column(Text)
    suggested_tags: Mapped[list | None] = mapped_column(JSONB)
    ai_backend: Mapped[str] = mapped_column(String(32), default="none")
    model_used: Mapped[str | None] = mapped_column(String(128))
    agent_steps: Mapped[int] = mapped_column(Integer, default=0)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="ai_analysis")


class AssetEvidence(Base):
    __tablename__ = "asset_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)          # ai | rule | mac_oui | probe_http | ...
    category: Mapped[str] = mapped_column(String(32), nullable=False)        # device_type | vendor | os | service | identity
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    details: Mapped[dict | None] = mapped_column(JSONB)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="evidence")


class ProbeRun(Base):
    __tablename__ = "probe_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    probe_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_port: Mapped[int | None] = mapped_column(Integer)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    duration_ms: Mapped[float | None] = mapped_column()
    summary: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict | None] = mapped_column(JSONB)
    raw_excerpt: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="probe_runs")


class PassiveObservation(Base):
    __tablename__ = "passive_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONB)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="observations")


class FingerprintHypothesis(Base):
    __tablename__ = "fingerprint_hypotheses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="ollama")
    device_type: Mapped[str | None] = mapped_column(String(64))
    vendor: Mapped[str | None] = mapped_column(String(256))
    model: Mapped[str | None] = mapped_column(String(256))
    os_guess: Mapped[str | None] = mapped_column(String(256))
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_evidence: Mapped[list | None] = mapped_column(JSONB)
    prompt_version: Mapped[str] = mapped_column(String(32), default="v1")
    model_used: Mapped[str | None] = mapped_column(String(128))
    raw_response: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="fingerprint_hypotheses")


class InternetLookupResult(Base):
    __tablename__ = "internet_lookup_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    query: Mapped[str] = mapped_column(String(512), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    snippet: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    looked_up_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="internet_lookup_results")


class LifecycleRecord(Base):
    __tablename__ = "lifecycle_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(128))
    support_status: Mapped[str] = mapped_column(String(32), nullable=False)
    eol_date: Mapped[str | None] = mapped_column(String(32))
    reference: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="lifecycle_records")


class AssetAutopsy(Base):
    __tablename__ = "asset_autopsies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(ASSET_ID_FK, ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    trace: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="autopsy")


class TopologyLink(Base):
    """Directed adjacency list for network topology graph."""
    __tablename__ = "topology_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"))
    link_type: Mapped[str] = mapped_column(String(32), default="ethernet")  # ethernet | wifi | vlan | vpn
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    link_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB)

    __table_args__ = (UniqueConstraint("source_id", "target_id", name="uq_topology_link"),)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    targets: Mapped[str] = mapped_column(Text, nullable=False)  # CIDR or IP list
    scan_type: Mapped[str] = mapped_column(String(32), default="full")  # full | quick | ports | snmp
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | running | paused | cancelled | done | failed
    triggered_by: Mapped[str] = mapped_column(String(32), default="schedule")  # schedule | manual | api
    queue_position: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    control_action: Mapped[str | None] = mapped_column(String(16))
    control_mode: Mapped[str | None] = mapped_column(String(32))
    resume_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete=SET_NULL))
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
        ForeignKey(ASSET_ID_FK, ondelete="CASCADE"),
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
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    target_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("config_backup_targets.id", ondelete=SET_NULL))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    driver: Mapped[str] = mapped_column(String(64), nullable=False)
    command: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WirelessAssociation(Base):
    __tablename__ = "wireless_associations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_point_asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    client_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete=SET_NULL))
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
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(ASSET_ID_FK, ondelete="CASCADE"), nullable=False)
    port_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("ports.id", ondelete=SET_NULL))
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
    host_chunk_size: Mapped[int] = mapped_column(Integer, default=64)
    top_ports_count: Mapped[int] = mapped_column(Integer, default=1000)
    deep_probe_timeout_seconds: Mapped[int] = mapped_column(Integer, default=6)
    ai_after_scan_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    passive_arp_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    passive_arp_interface: Mapped[str] = mapped_column(String(64), default="eth0")
    snmp_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    snmp_version: Mapped[str] = mapped_column(String(8), default="2c")
    snmp_community: Mapped[str] = mapped_column(String(128), default="public")
    snmp_timeout: Mapped[int] = mapped_column(Integer, default=5)
    snmp_v3_username: Mapped[str | None] = mapped_column(String(128))
    snmp_v3_auth_key: Mapped[str | None] = mapped_column(String(256))
    snmp_v3_priv_key: Mapped[str | None] = mapped_column(String(256))
    snmp_v3_auth_protocol: Mapped[str] = mapped_column(String(16), default="sha")
    snmp_v3_priv_protocol: Mapped[str] = mapped_column(String(16), default="aes")
    fingerprint_ai_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    fingerprint_ai_model: Mapped[str | None] = mapped_column(String(128))
    fingerprint_ai_min_confidence: Mapped[float] = mapped_column(default=0.75)
    fingerprint_ai_prompt_suffix: Mapped[str | None] = mapped_column(Text)
    internet_lookup_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    internet_lookup_allowed_domains: Mapped[str | None] = mapped_column(Text)
    internet_lookup_budget: Mapped[int] = mapped_column(Integer, default=3)
    internet_lookup_timeout_seconds: Mapped[int] = mapped_column(Integer, default=5)
    last_scheduled_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class FingerprintDataset(Base):
    __tablename__ = "fingerprint_datasets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    upstream_url: Mapped[str] = mapped_column(Text, nullable=False)
    local_path: Mapped[str | None] = mapped_column(Text)
    update_mode: Mapped[str] = mapped_column(String(32), default="remote")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    upstream_last_modified: Mapped[str | None] = mapped_column(String(128))
    etag: Mapped[str | None] = mapped_column(String(128))
    sha256: Mapped[str | None] = mapped_column(String(64))
    record_count: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class TplinkDecoConfig(Base):
    __tablename__ = "tplink_deco_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    base_url: Mapped[str] = mapped_column(String(255), default="http://tplinkdeco.net")
    owner_username: Mapped[str | None] = mapped_column(String(128))
    owner_password: Mapped[str | None] = mapped_column(String(256))
    fetch_connected_clients: Mapped[bool] = mapped_column(Boolean, default=True)
    fetch_portal_logs: Mapped[bool] = mapped_column(Boolean, default=True)
    request_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String(32), default="idle")
    last_error: Mapped[str | None] = mapped_column(Text)
    last_client_count: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class TplinkDecoSyncRun(Base):
    __tablename__ = "tplink_deco_sync_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    client_count: Mapped[int | None] = mapped_column(Integer)
    clients_payload: Mapped[list | None] = mapped_column(JSONB)
    logs_excerpt: Mapped[str | None] = mapped_column(Text)
    log_analysis: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
