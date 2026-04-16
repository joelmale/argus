from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from re import Pattern
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import FingerprintDataset

DATASET_DIR = Path(__file__).resolve().parents[2] / "data" / "fingerprint_datasets"


@dataclass(frozen=True, slots=True)
class DatasetDefinition:
    key: str
    name: str
    category: str
    description: str
    upstream_url: str
    filename: str
    update_mode: str = "remote"
    notes: dict | None = None


@dataclass(frozen=True, slots=True)
class RecogParam:
    name: str
    pos: int
    value: str | None


@dataclass(frozen=True, slots=True)
class RecogFingerprint:
    pattern_text: str
    pattern: Pattern[str]
    description: str | None
    params: tuple[RecogParam, ...]


DATASET_DEFINITIONS: tuple[DatasetDefinition, ...] = (
    DatasetDefinition(
        key="ieee_oui_official",
        name="IEEE OUI Registry",
        category="mac_vendor",
        description="Official IEEE OUI registry. Some automated fetches may be rate-limited by IEEE.",
        upstream_url="https://standards-oui.ieee.org/oui/oui.txt",
        filename="ieee_oui.txt",
        notes={"format": "text", "used_for": ["mac_vendor"]},
    ),
    DatasetDefinition(
        key="wireshark_manuf",
        name="Wireshark manuf",
        category="mac_vendor",
        description="Wireshark manufacturer mapping, used as a reliable local MAC vendor fallback.",
        upstream_url="https://www.wireshark.org/download/automated/data/manuf",
        filename="wireshark_manuf.txt",
        notes={"format": "text", "used_for": ["mac_vendor"]},
    ),
    DatasetDefinition(
        key="iana_pen",
        name="IANA Private Enterprise Numbers",
        category="snmp",
        description="Maps SNMP private enterprise numbers to vendors for sysObjectID enrichment.",
        upstream_url="https://www.iana.org/assignments/enterprise-numbers.txt",
        filename="iana_pen.txt",
        notes={"format": "text", "used_for": ["snmp_vendor"]},
    ),
    DatasetDefinition(
        key="rapid7_recog_http",
        name="Rapid7 Recog HTTP Server Fingerprints",
        category="banner",
        description="Rapid7 Recog HTTP server fingerprint database for future banner matching expansion.",
        upstream_url="https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml",
        filename="rapid7_recog_http.xml",
        notes={"format": "xml", "used_for": ["http_banner"]},
    ),
    DatasetDefinition(
        key="nmap_os_db",
        name="Nmap OS Fingerprint Database",
        category="os_fingerprint",
        description="Nmap OS fingerprint database metadata snapshot for reference and future enrichment.",
        upstream_url="https://svn.nmap.org/nmap/nmap-os-db",
        filename="nmap-os-db",
        notes={"format": "text", "used_for": ["os_fingerprint"]},
    ),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _definition_map() -> dict[str, DatasetDefinition]:
    return {definition.key: definition for definition in DATASET_DEFINITIONS}


def _dataset_path(definition: DatasetDefinition) -> Path:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    return DATASET_DIR / definition.filename


async def get_or_seed_datasets(db: AsyncSession) -> list[FingerprintDataset]:
    existing = (await db.execute(select(FingerprintDataset))).scalars().all()
    by_key = {row.key: row for row in existing}
    changed = False
    for definition in DATASET_DEFINITIONS:
        if definition.key in by_key:
            row = by_key[definition.key]
            row.name = definition.name
            row.category = definition.category
            row.description = definition.description
            row.upstream_url = definition.upstream_url
            row.update_mode = definition.update_mode
            row.notes = definition.notes
            if not row.local_path:
                row.local_path = str(_dataset_path(definition))
            continue
        row = FingerprintDataset(
            key=definition.key,
            name=definition.name,
            category=definition.category,
            description=definition.description,
            upstream_url=definition.upstream_url,
            local_path=str(_dataset_path(definition)),
            update_mode=definition.update_mode,
            status="pending",
            notes=definition.notes,
        )
        db.add(row)
        existing.append(row)
        changed = True
    if changed:
        await db.flush()
    return sorted(existing, key=lambda item: (item.category, item.name))


def _fetch_bytes(url: str) -> tuple[bytes, dict[str, str]]:
    request = Request(url, headers={"User-Agent": "Argus/1.0 (+https://github.com/joelmale/argus)"})
    with urlopen(request, timeout=20) as response:
        payload = response.read()
        headers = {
            "last_modified": response.headers.get("Last-Modified") or "",
            "etag": response.headers.get("ETag") or "",
            "content_type": response.headers.get_content_type(),
        }
        return payload, headers


def _count_records(dataset_key: str, text: str) -> int | None:
    if dataset_key == "wireshark_manuf":
        return sum(1 for line in text.splitlines() if line and not line.startswith("#"))
    if dataset_key == "ieee_oui_official":
        return sum(1 for line in text.splitlines() if "(hex)" in line)
    if dataset_key == "iana_pen":
        return sum(1 for line in text.splitlines() if re.match(r"^\d+", line))
    if dataset_key == "rapid7_recog_http":
        return text.count("<fingerprint ")
    if dataset_key == "nmap_os_db":
        return text.count("\nFingerprint ")
    return None


async def refresh_dataset(db: AsyncSession, key: str) -> FingerprintDataset:
    datasets = await get_or_seed_datasets(db)
    row = next((item for item in datasets if item.key == key), None)
    if row is None:
        raise ValueError(f"Unknown dataset '{key}'")

    row.last_checked_at = _now()
    path = Path(row.local_path or _dataset_path(_definition_map()[row.key]))
    try:
        payload, headers = _fetch_bytes(row.upstream_url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        text = payload.decode("utf-8", "ignore")
        row.local_path = str(path)
        row.upstream_last_modified = headers.get("last_modified") or None
        row.etag = headers.get("etag") or None
        row.sha256 = hashlib.sha256(payload).hexdigest()
        row.record_count = _count_records(row.key, text)
        row.status = "ready"
        row.error = None
        row.last_updated_at = _now()
        _clear_caches()
    except HTTPError as exc:
        row.status = "error"
        row.error = f"HTTP {exc.code}: {exc.reason}"
    except URLError as exc:
        row.status = "error"
        row.error = f"Network error: {exc.reason}"
    except Exception as exc:
        row.status = "error"
        row.error = str(exc)

    await db.flush()
    return row


async def list_datasets(db: AsyncSession) -> list[FingerprintDataset]:
    return await get_or_seed_datasets(db)


def _clear_caches() -> None:
    load_mac_vendor_dataset.cache_clear()
    load_iana_pen_dataset.cache_clear()
    load_rapid7_recog_http_dataset.cache_clear()


def _read_dataset_file(filename: str) -> str:
    path = DATASET_DIR / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


@lru_cache(maxsize=1)
def load_mac_vendor_dataset() -> dict[str, str]:
    data: dict[str, str] = {}
    wireshark = _read_dataset_file("wireshark_manuf.txt")
    for line in wireshark.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\t+", line)
        if len(parts) < 2:
            continue
        prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()
        if len(prefix) < 6:
            continue
        data[prefix[:6]] = parts[1].strip()

    ieee = _read_dataset_file("ieee_oui.txt")
    for line in ieee.splitlines():
        if " (hex) " not in line:
            continue
        prefix, vendor = line.split(" (hex) ", 1)
        prefix = prefix.strip().upper()
        vendor = vendor.strip()
        if len(prefix) == 6 and all(char in "0123456789ABCDEF" for char in prefix) and vendor:
            data.setdefault(prefix, vendor)
    return data


@lru_cache(maxsize=1)
def load_iana_pen_dataset() -> dict[str, str]:
    data: dict[str, str] = {}
    text = _read_dataset_file("iana_pen.txt")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        pen, vendor = parts
        if pen.isdigit() and vendor.strip():
            data[pen] = vendor.strip()
    return data


@lru_cache(maxsize=1)
def load_rapid7_recog_http_dataset() -> tuple[RecogFingerprint, ...]:
    text = _read_dataset_file("rapid7_recog_http.xml")
    if not text:
        return ()
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return ()

    fingerprints: list[RecogFingerprint] = []
    for node in root.findall("fingerprint"):
        pattern_text = node.attrib.get("pattern")
        if not pattern_text:
            continue
        try:
            pattern = re.compile(pattern_text)
        except re.error:
            continue
        params: list[RecogParam] = []
        for param_node in node.findall("param"):
            name = param_node.attrib.get("name")
            if not name:
                continue
            params.append(
                RecogParam(
                    name=name,
                    pos=_safe_int(param_node.attrib.get("pos"), default=0),
                    value=param_node.attrib.get("value"),
                )
            )
        description = node.findtext("description")
        fingerprints.append(
            RecogFingerprint(
                pattern_text=pattern_text,
                pattern=pattern,
                description=description.strip() if description else None,
                params=tuple(params),
            )
        )
    return tuple(fingerprints)


def match_rapid7_recog_http_server(server_header: str | None) -> dict[str, str] | None:
    if not server_header:
        return None
    header = server_header.strip()
    if not header:
        return None

    for fingerprint in load_rapid7_recog_http_dataset():
        match = fingerprint.pattern.search(header)
        if not match:
            continue
        values = _extract_recog_values(fingerprint, match)
        if not values:
            continue
        values["recog.pattern"] = fingerprint.pattern_text
        values["recog.description"] = fingerprint.description or ""
        return values
    return None


def _extract_recog_values(fingerprint: RecogFingerprint, match: re.Match[str]) -> dict[str, str]:
    raw_values: dict[str, str] = {}
    for param in fingerprint.params:
        value = param.value
        if value is None:
            try:
                value = match.group(param.pos)
            except IndexError:
                value = None
        if value:
            raw_values[param.name] = value
    return {key: _expand_recog_value(value, raw_values) for key, value in raw_values.items()}


def _expand_recog_value(value: str, values: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        return values.get(match.group(1), "")

    return re.sub(r"\{([^}]+)\}", replace, value)


def _safe_int(value: str | None, *, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def lookup_mac_vendor_from_dataset(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()[:6]
    if len(prefix) < 6:
        return None
    return load_mac_vendor_dataset().get(prefix)


def lookup_pen_vendor(sys_object_id: str | None) -> str | None:
    if not sys_object_id:
        return None
    match = re.search(r"(?:^|\.)1\.3\.6\.1\.4\.1\.(\d+)", sys_object_id)
    if not match:
        return None
    return load_iana_pen_dataset().get(match.group(1))
