from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_audit_event
from app.db.models import Asset, AssetTag, TplinkDecoConfig, TplinkDecoSyncRun, User
from app.fingerprinting.passive import record_passive_observation
from app.services.identity import AssetIdentityResolver
from app.scanner.topology import _upsert_topology_link
from app.topology.segments import ensure_segment_for_asset

DEFAULT_DECO_OWNER_USERNAME = "admin"
DECO_ISSUE_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
DECO_LOG_EXPORT_ATTEMPTS = [
    {"data": {"operation": "save"}},
    {"data": {"operation": "save"}, "files": {"save-log-file": ("", "")}},
    {"data": {"operation": "save"}, "files": {"save-log-file": ("save-log.txt", b"", "text/plain")}},
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_base_url(value: str | None) -> str:
    raw = (value or "http://tplinkdeco.net").strip()
    if not raw:
        raw = "http://tplinkdeco.net"
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    return raw.rstrip("/")


def _md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _rsa_public_key(modulus_hex: str, exponent_hex: str):
    return rsa.RSAPublicNumbers(int(exponent_hex, 16), int(modulus_hex, 16)).public_key()


def _rsa_encrypt_pkcs1_v15_hex(modulus_hex: str, exponent_hex: str, plaintext: str) -> str:
    key = _rsa_public_key(modulus_hex, exponent_hex)
    ciphertext = key.encrypt(plaintext.encode("utf-8"), asym_padding.PKCS1v15())  # NOSONAR - TP-Link protocol requires PKCS#1 v1.5
    return ciphertext.hex().upper()


def _aes_encrypt_base64(key: str, iv: str, plaintext: str) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key.encode("utf-8")), modes.CBC(iv.encode("utf-8")))  # NOSONAR - TP-Link protocol requires AES-CBC framing
    encryptor = cipher.encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize())


def _aes_decrypt_json(key: str, iv: str, payload: str) -> dict[str, Any]:
    cipher = Cipher(algorithms.AES(key.encode("utf-8")), modes.CBC(iv.encode("utf-8")))  # NOSONAR - TP-Link protocol requires AES-CBC framing
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(base64.b64decode(payload)) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(plaintext) + unpadder.finalize()
    return json.loads(data.decode("utf-8"))


def _rand16() -> str:
    return secrets.token_hex(8)


def _parse_cookie_sysauth(headers: httpx.Headers) -> str | None:
    cookie = headers.get("set-cookie", "")
    match = re.search(r"sysauth=([^;]+)", cookie)
    return match.group(1) if match else None


def _coalesce_str(data: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().replace("-", ":").upper()
    if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", cleaned):
        return cleaned
    return None


def _effective_owner_username(value: str | None) -> str:
    # Deco's local portal hides the username field, but the auth signature
    # still uses the admin username by default.
    return (value or "").strip() or DEFAULT_DECO_OWNER_USERNAME


def _decode_deco_label(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
        return decoded.strip() or text
    except Exception:
        return text


def _deco_name_key(value: str | None) -> str | None:
    text = (value or "").strip().lower()
    return text or None


def _parse_deco_log_summary(raw_text: str) -> str:
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not lines:
        return ""

    counters = _empty_deco_log_counters()
    client_macs: set[str] = set()

    for line in lines:
        _update_deco_log_counters(counters, line)
        _collect_uppercase_log_macs(line, client_macs)

    summary_lines = ["# Parsed Deco Log Summary"]
    for key, value in counters.items():
        if value:
            summary_lines.append(f"{key}: {value}")
    if client_macs:
        summary_lines.append(f"unique_macs_observed: {len(client_macs)}")
    if len(summary_lines) == 1:
        return ""
    return "\n".join(summary_lines)


def _empty_deco_log_counters() -> dict[str, int]:
    return {
        "wifi_client_associations": 0,
        "wifi_handshakes_completed": 0,
        "80211k_timeouts": 0,
        "steering_engine_errors": 0,
        "invalid_message_events": 0,
        "mesh_band_mismatch_events": 0,
    }


def _update_deco_log_counters(counters: dict[str, int], line: str) -> None:
    upper = line.upper()
    if _is_client_association_line(upper):
        counters["wifi_client_associations"] += 1
    if "EAPOL-4WAY-HS-COMPLETED" in upper:
        counters["wifi_handshakes_completed"] += 1
    if "TIMEOUT WAITING FOR 802.11K RESPONSE" in upper:
        counters["80211k_timeouts"] += 1
    if "STEERALG" in upper:
        counters["steering_engine_errors"] += 1
    if "INVALID MESSAGE LEN" in upper:
        counters["invalid_message_events"] += 1
    if "TARGETBAND" in upper and "MEASUREDBSS" in upper:
        counters["mesh_band_mismatch_events"] += 1


def _is_client_association_line(upper: str) -> bool:
    return (
        "AP-STA-CONNECTED" in upper
        or 'ACTION":"ASSOCIATE' in upper
        or "ACTION:ASSOCIATE" in upper
    )


def _collect_uppercase_log_macs(line: str, client_macs: set[str]) -> None:
    upper = line.upper()
    for match in re.findall(r"(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}", upper):
        client_macs.add(match.replace("-", ":"))


def analyze_deco_logs(raw_text: str) -> dict[str, Any]:
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not lines:
        return _empty_log_analysis()

    pattern_catalog = _deco_log_pattern_catalog()

    issue_map, observed_macs = _collect_deco_log_matches(lines, pattern_catalog)
    issues, total_penalty = _build_deco_issues(issue_map)
    recommendations = _build_deco_recommendations(issues)

    return {
        "health_score": max(0, 100 - total_penalty),
        "event_count": len(lines),
        "issues": issues,
        "recommendations": recommendations,
        "observed_macs": sorted(observed_macs),
    }


def _empty_log_analysis() -> dict[str, Any]:
    return {
        "health_score": 100,
        "event_count": 0,
        "issues": [],
        "recommendations": [],
        "observed_macs": [],
    }


def _deco_log_pattern_catalog() -> list[dict[str, Any]]:
    return [
        {
            "key": "band_steering_mismatch",
            "title": "Aggressive band steering mismatch",
            "severity": "medium",
            "regex": re.compile(r"targetBand\((?P<target>\d+)\)\s*!=\s*measuredBss->band\((?P<measured>\d+)\)", re.IGNORECASE),
            "issue": "Band steering is attempting to push a client onto a band that does not match the measured BSS state.",
            "recommendation": "Disable Smart Connect temporarily or split 2.4 GHz / 5 GHz SSIDs if clients are being steered too aggressively.",
            "health_penalty": 3,
        },
        {
            "key": "mesh_sync_missing_apinfo",
            "title": "Mesh neighbor database inconsistency",
            "severity": "medium",
            "regex": re.compile(r"Cannot find (?P<mac>(?:[0-9A-F]{2}:){5}[0-9A-F]{2}) in apinfo list", re.IGNORECASE),
            "issue": "The controller cannot reconcile a neighbor BSSID with its mesh state table.",
            "recommendation": "Restart the affected mesh node or run the Deco network optimization workflow to rebuild neighbor state.",
            "health_penalty": 4,
        },
        {
            "key": "k11_timeout",
            "title": "802.11k roaming timeout",
            "severity": "high",
            "regex": re.compile(r"Timeout waiting for 802\.11k response from (?P<mac>(?:[0-9A-F]{2}:){5}[0-9A-F]{2})", re.IGNORECASE),
            "issue": "A client did not answer an 802.11k measurement request during roaming evaluation.",
            "recommendation": "Check whether the client is near the edge of coverage or lacks solid 802.11k/v/r support. Consider relaxing roaming aggressiveness for that device.",
            "health_penalty": 6,
        },
        {
            "key": "dead_zone_rate",
            "title": "Potential dead zone or weak backhaul",
            "severity": "high",
            "regex": re.compile(r"(estimated pat datarate is 0|patrate .* is 0\b)", re.IGNORECASE),
            "issue": "The AP calculated zero viable data rate for a path, which usually indicates severe interference or an overly weak link.",
            "recommendation": "Move the affected mesh node closer to the main router or reduce physical interference between nodes.",
            "health_penalty": 8,
        },
        {
            "key": "signal_flapping",
            "title": "Roaming threshold instability",
            "severity": "medium",
            "regex": re.compile(r"update 11K Threshold.*old.*newthreshold", re.IGNORECASE),
            "issue": "The controller is repeatedly recalculating roaming thresholds, suggesting unstable RSSI around the handoff boundary.",
            "recommendation": "Increase the roaming threshold slightly or improve coverage overlap so clients stop bouncing between APs.",
            "health_penalty": 3,
        },
        {
            "key": "beacon_report_state",
            "title": "Unexpected beacon-report state",
            "severity": "medium",
            "regex": re.compile(r"Beacon report .* unexpected state (?P<state>\d+)", re.IGNORECASE),
            "issue": "A client is producing out-of-sequence or unsupported beacon-report behavior during steering logic.",
            "recommendation": "Toggle Wi-Fi on the device, update its firmware, or disable fast roaming for that MAC if the issue repeats.",
            "health_penalty": 4,
        },
        {
            "key": "ssh_management_load",
            "title": "High management polling load",
            "severity": "low",
            "regex": re.compile(r"Pubkey auth succeeded for 'root'", re.IGNORECASE),
            "issue": "An external tool is logging in over SSH often enough to show up in the AP logs.",
            "recommendation": "Increase polling intervals in external monitoring or automation tools to reduce CPU overhead on the Deco node.",
            "health_penalty": 2,
        },
        {
            "key": "invalid_message_length",
            "title": "Controller message framing error",
            "severity": "medium",
            "regex": re.compile(r"Invalid message len:\s*(?P<length>\d+)\s*bytes", re.IGNORECASE),
            "issue": "The steering process received malformed or truncated controller messages.",
            "recommendation": "Reboot the affected node and check whether its firmware is aligned with the rest of the mesh.",
            "health_penalty": 4,
        },
        {
            "key": "client_association",
            "title": "Client association activity",
            "severity": "info",
            "regex": re.compile(r"(AP-STA-CONNECTED|client_action:associate|action\":\"associate\")", re.IGNORECASE),
            "issue": "A client successfully associated with the AP.",
            "recommendation": "No action required unless the same client repeatedly reconnects in a short window.",
            "health_penalty": 0,
        },
    ]


def _collect_deco_log_matches(lines: list[str], pattern_catalog: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    issue_map: dict[str, dict[str, Any]] = {}
    observed_macs: set[str] = set()
    for line in lines:
        _collect_observed_macs(line, observed_macs)
        for pattern in pattern_catalog:
            _record_pattern_match(issue_map, pattern, line)
    return issue_map, observed_macs


def _collect_observed_macs(line: str, observed_macs: set[str]) -> None:
    normalized_line = line.replace("-", ":").upper()
    for mac in re.findall(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", normalized_line):
        observed_macs.add(mac)


def _record_pattern_match(issue_map: dict[str, dict[str, Any]], pattern: dict[str, Any], line: str) -> None:
    match = pattern["regex"].search(line)
    if not match:
        return
    bucket = issue_map.setdefault(
        pattern["key"],
        {
            "key": pattern["key"],
            "title": pattern["title"],
            "severity": pattern["severity"],
            "issue": pattern["issue"],
            "recommendation": pattern["recommendation"],
            "count": 0,
            "sample_lines": [],
            "affected_macs": set(),
            "health_penalty": pattern["health_penalty"],
        },
    )
    bucket["count"] += 1
    if len(bucket["sample_lines"]) < 3:
        bucket["sample_lines"].append(line)
    _add_match_group_macs(bucket["affected_macs"], match.groupdict().values())


def _add_match_group_macs(affected_macs: set[str], values) -> None:
    for value in values:
        if isinstance(value, str) and re.fullmatch(r"(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}", value, re.IGNORECASE):
            affected_macs.add(value.replace("-", ":").upper())


def _build_deco_issues(issue_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    issues: list[dict[str, Any]] = []
    total_penalty = 0
    for item in issue_map.values():
        scaled_penalty = item["health_penalty"] * min(item["count"], 5)
        total_penalty += scaled_penalty
        issues.append(
            {
                "key": item["key"],
                "title": item["title"],
                "severity": item["severity"],
                "issue": item["issue"],
                "recommendation": item["recommendation"],
                "count": item["count"],
                "health_penalty": scaled_penalty,
                "sample_lines": item["sample_lines"],
                "affected_macs": sorted(item["affected_macs"]),
            }
        )
    issues.sort(key=lambda item: (DECO_ISSUE_SEVERITY_ORDER.get(item["severity"], 9), -item["count"], item["title"]))
    return issues, total_penalty


def _build_deco_recommendations(issues: list[dict[str, Any]]) -> list[dict[str, str]]:
    recommendations: list[dict[str, str]] = []
    seen_recommendations: set[str] = set()
    for issue in issues:
        recommendation = issue["recommendation"]
        if recommendation in seen_recommendations:
            continue
        seen_recommendations.add(recommendation)
        recommendations.append(
            {
                "title": issue["title"],
                "severity": issue["severity"],
                "recommendation": recommendation,
            }
        )
    return recommendations


@dataclass(slots=True)
class DecoClientRecord:
    mac: str | None
    ip: str | None
    hostname: str | None
    nickname: str | None
    device_model: str | None
    connection_type: str | None
    access_point_name: str | None
    raw: dict[str, Any]


@dataclass(slots=True)
class DecoDeviceRecord:
    mac: str | None
    ip: str | None
    hostname: str | None
    nickname: str | None
    model: str | None
    role: str | None
    software_version: str | None
    hardware_version: str | None
    raw: dict[str, Any]


@dataclass(slots=True)
class DecoLogPage:
    entries: list[str]
    total_pages: int
    current_index: int


def normalize_deco_client(record: dict[str, Any]) -> DecoClientRecord:
    return DecoClientRecord(
        mac=_normalize_mac(_coalesce_str(record, ["mac", "client_mac", "mac_addr"])),
        ip=_coalesce_str(record, ["ip", "ip_addr", "ipv4", "client_ip"]),
        hostname=_decode_deco_label(_coalesce_str(record, ["name", "hostname", "host_name"])),
        nickname=_decode_deco_label(_coalesce_str(record, ["nickname", "device_name", "alias"])),
        device_model=_coalesce_str(record, ["device_model", "model", "device_type", "brand"]),
        connection_type=_coalesce_str(record, ["interface", "connection_type", "connect_type", "wire_type"]),
        access_point_name=_coalesce_str(record, ["master_device_name", "ap_name", "slave_name", "mesh_node_name"]),
        raw=record,
    )


def normalize_deco_device(record: dict[str, Any]) -> DecoDeviceRecord:
    nickname = _decode_deco_label(_coalesce_str(record, ["custom_nickname", "nickname", "alias"]))
    hostname = nickname or _decode_deco_label(_coalesce_str(record, ["name", "hostname"]))
    return DecoDeviceRecord(
        mac=_normalize_mac(_coalesce_str(record, ["mac", "mac_addr"])),
        ip=_coalesce_str(record, ["device_ip", "ip", "ip_addr"]),
        hostname=hostname,
        nickname=nickname,
        model=_coalesce_str(record, ["device_model", "model"]),
        role=_coalesce_str(record, ["role", "device_role"]),
        software_version=_coalesce_str(record, ["software_ver", "software_version"]),
        hardware_version=_coalesce_str(record, ["hardware_ver", "hardware_version"]),
        raw=record,
    )


class TplinkDecoClient:
    def __init__(self, *, base_url: str, owner_username: str | None, owner_password: str, timeout_seconds: int = 10, verify_tls: bool = False):
        self.base_url = _normalize_base_url(base_url)
        self.owner_username = _effective_owner_username(owner_username)
        self.owner_password = owner_password
        self.timeout_seconds = max(3, timeout_seconds)
        self.verify_tls = verify_tls
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
            follow_redirects=True,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self._aes_key = _rand16()
        self._aes_iv = _rand16()
        self._password_hash = _md5_hex(f"{self.owner_username}{self.owner_password}")
        self._request_key: tuple[str, str] | None = None
        self._password_key: tuple[str, str] | None = None
        self._sequence: int | None = None
        self.stok: str | None = None
        self.sysauth: str | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "TplinkDecoClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _plain_form_read(self, form: str) -> dict[str, Any]:
        response = await self._client.post("/cgi-bin/luci/;stok=/login", params={"form": form}, json={"operation": "read"})
        response.raise_for_status()
        data = response.json()
        if data.get("error_code") not in (0, None):
            raise RuntimeError(data.get("msg") or data.get("error_code") or f"Deco portal returned an error for {form}")
        return data

    async def bootstrap(self) -> None:
        keys = await self._plain_form_read("keys")
        auth = await self._plain_form_read("auth")
        self._password_key = tuple(keys["result"]["password"])
        self._request_key = tuple(auth["result"]["key"])
        self._sequence = int(auth["result"]["seq"])

    def _build_login_payload(self) -> tuple[str, bytes]:
        if self._password_key is None or self._request_key is None or self._sequence is None:
            raise RuntimeError("Deco auth bootstrap has not completed")

        password_hex = _rsa_encrypt_pkcs1_v15_hex(self._password_key[0], self._password_key[1], self.owner_password)
        auth_data = json.dumps({"params": {"password": password_hex}, "operation": "login"})
        ciphertext = _aes_encrypt_base64(self._aes_key, self._aes_iv, auth_data)
        sign_plain = f"k={self._aes_key}&i={self._aes_iv}&h={self._password_hash}&s={self._sequence + len(ciphertext)}"
        if len(sign_plain) > 53:
            sign = (
                _rsa_encrypt_pkcs1_v15_hex(self._request_key[0], self._request_key[1], sign_plain[:53])
                + _rsa_encrypt_pkcs1_v15_hex(self._request_key[0], self._request_key[1], sign_plain[53:])
            )
        else:
            sign = _rsa_encrypt_pkcs1_v15_hex(self._request_key[0], self._request_key[1], sign_plain)
        return sign, ciphertext

    async def login(self) -> dict[str, Any]:
        if self._password_key is None or self._request_key is None:
            await self.bootstrap()

        sign, payload = self._build_login_payload()
        response = await self._client.post(
            "/cgi-bin/luci/;stok=/login",
            params={"form": "login"},
            data={"sign": sign, "data": payload},
            headers={"Referer": f"{self.base_url}/webpages/index.html"},
        )
        response.raise_for_status()
        body = response.json()
        decrypted = _aes_decrypt_json(self._aes_key, self._aes_iv, body["data"])
        self.stok = decrypted["result"]["stok"]
        self.sysauth = _parse_cookie_sysauth(response.headers)
        if not self.stok or not self.sysauth:
            raise RuntimeError("Deco login succeeded without returning stok/sysauth")
        return decrypted

    def _build_encrypted_request(self, payload: dict[str, Any]) -> tuple[str, bytes]:
        if self._request_key is None or self._sequence is None:
            raise RuntimeError("Deco auth bootstrap has not completed")
        encoded = _aes_encrypt_base64(self._aes_key, self._aes_iv, json.dumps(payload))
        sign_plain = f"h={self._password_hash}&s={self._sequence + len(encoded)}"
        if len(sign_plain) > 53:
            sign = (
                _rsa_encrypt_pkcs1_v15_hex(self._request_key[0], self._request_key[1], sign_plain[:53])
                + _rsa_encrypt_pkcs1_v15_hex(self._request_key[0], self._request_key[1], sign_plain[53:])
            )
        else:
            sign = _rsa_encrypt_pkcs1_v15_hex(self._request_key[0], self._request_key[1], sign_plain)
        return sign, encoded

    async def encrypted_request(self, path: str, *, form: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.stok or not self.sysauth:
            await self.login()
        sign, data = self._build_encrypted_request(payload)
        response = await self._client.post(
            f"/cgi-bin/luci/;stok={self.stok}{path}",
            params={"form": form},
            data={"sign": sign, "data": data},
            cookies={"sysauth": self.sysauth},
            headers={
                "Referer": f"{self.base_url}/webpages/index.html",
                "Origin": f"{urlparse(self.base_url).scheme}://{urlparse(self.base_url).netloc}",
            },
        )
        response.raise_for_status()
        body = response.json()
        if "data" not in body:
            return body
        decrypted = _aes_decrypt_json(self._aes_key, self._aes_iv, body["data"])
        if decrypted.get("error_code") not in (0, None):
            raise RuntimeError(decrypted.get("msg") or decrypted.get("error_code") or "Deco encrypted request failed")
        return decrypted

    async def fetch_connected_clients(self) -> list[DecoClientRecord]:
        response = await self.encrypted_request(
            "/admin/client",
            form="client_list",
            payload={"operation": "read", "params": {"device_mac": "default"}},
        )
        clients = response.get("result", {}).get("client_list", [])
        return [normalize_deco_client(row) for row in clients if isinstance(row, dict)]

    async def fetch_deco_devices(self) -> list[DecoDeviceRecord]:
        response = await self.encrypted_request(
            "/admin/device",
            form="device_list",
            payload={"operation": "read"},
        )
        devices = response.get("result", {}).get("device_list", [])
        return [normalize_deco_device(row) for row in devices if isinstance(row, dict)]

    async def _fetch_feedback_log_page(self, *, level: int = 5, index: int = 0, limit: int = 100) -> DecoLogPage:
        if not self.stok or not self.sysauth:
            await self.login()
        response = await self._client.post(
            f"/cgi-bin/luci/;stok={self.stok}/admin/log_export",
            params={"form": "feedback_log"},
            data={"operation": "build", "level": str(level), "index": str(index), "limit": str(limit)},
            cookies={"sysauth": self.sysauth},
            headers={"Referer": f"{self.base_url}/webpages/index.html"},
        )
        response.raise_for_status()
        body = response.json()
        if body.get("error_code") not in (0, None):
            raise RuntimeError(body.get("msg") or body.get("error_code") or "Deco feedback log request failed")

        log_list = body.get("logList") or []
        entries: list[str] = []
        for item in log_list:
            if not isinstance(item, dict):
                continue
            # The UI information panel renders the `content` field directly.
            content = str(item.get("content") or "").strip()
            if content:
                entries.append(content)
        total_pages = int(body.get("totalNum") or 0)
        current_index = int(body.get("currentIndex") or index)
        return DecoLogPage(entries=entries, total_pages=total_pages, current_index=current_index)

    async def _attempt_save_log_export(self) -> str | None:
        if not self.stok or not self.sysauth:
            await self.login()

        for payload in DECO_LOG_EXPORT_ATTEMPTS:
            response = await self._client.post(
                f"/cgi-bin/luci/;stok={self.stok}/admin/log_export",
                params={"form": "save_log"},
                cookies={"sysauth": self.sysauth},
                headers={"Referer": f"{self.base_url}/webpages/index.html"},
                **payload,
            )
            exported = _parse_log_export_response(response)
            if exported is not None:
                return exported
        return None

    async def fetch_portal_logs(self) -> str | None:
        # The live system-log page reads from `feedback_log` with paging. Argus
        # assembles the same pages into one exportable text blob so log analysis
        # does not depend on the brittle `save_log` upload helper.
        first_page = await self._fetch_feedback_log_page(level=5, index=0, limit=100)
        entries = list(first_page.entries)

        total_pages = max(first_page.total_pages, 1)
        for index in range(1, total_pages):
            page = await self._fetch_feedback_log_page(level=5, index=index, limit=100)
            entries.extend(page.entries)

        deduped_entries = list(dict.fromkeys(entry for entry in entries if entry))
        assembled = "\n".join(deduped_entries).strip()
        exported = await self._attempt_save_log_export()
        if exported:
            return exported
        return assembled or None

    async def logout(self) -> None:
        if not self.stok:
            return
        try:
            await self._client.post(
                f"/cgi-bin/luci/;stok={self.stok}/admin/system",
                params={"form": "logout", "operation": "write"},
                cookies={"sysauth": self.sysauth},
                headers={"Referer": f"{self.base_url}/webpages/index.html"},
            )
        finally:
            self.stok = None
            self.sysauth = None


async def get_or_create_tplink_deco_config(db: AsyncSession) -> TplinkDecoConfig:
    config = (await db.execute(select(TplinkDecoConfig).limit(1))).scalar_one_or_none()
    if config is not None:
        return config
    config = TplinkDecoConfig()
    db.add(config)
    await db.flush()
    return config


def serialize_tplink_deco_config(config: TplinkDecoConfig) -> dict[str, Any]:
    return {
        "id": config.id,
        "enabled": config.enabled,
        "base_url": config.base_url,
        "owner_username": config.owner_username,
        "effective_owner_username": _effective_owner_username(config.owner_username),
        "owner_password": config.owner_password,
        "fetch_connected_clients": config.fetch_connected_clients,
        "fetch_portal_logs": config.fetch_portal_logs,
        "request_timeout_seconds": config.request_timeout_seconds,
        "verify_tls": config.verify_tls,
        "last_tested_at": config.last_tested_at.isoformat() if config.last_tested_at else None,
        "last_sync_at": config.last_sync_at.isoformat() if config.last_sync_at else None,
        "last_status": config.last_status,
        "last_error": config.last_error,
        "last_client_count": config.last_client_count,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }


def serialize_tplink_deco_sync_run(row: TplinkDecoSyncRun) -> dict[str, Any]:
    return {
        "id": row.id,
        "status": row.status,
        "client_count": row.client_count,
        "clients_payload": row.clients_payload or [],
        "logs_excerpt": row.logs_excerpt,
        "log_analysis": row.log_analysis,
        "error": row.error,
        "started_at": row.started_at.isoformat(),
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }


async def list_recent_tplink_deco_sync_runs(db: AsyncSession, limit: int = 5) -> list[TplinkDecoSyncRun]:
    result = await db.execute(select(TplinkDecoSyncRun).order_by(desc(TplinkDecoSyncRun.started_at)).limit(limit))
    return list(result.scalars().all())


async def update_tplink_deco_config(
    db: AsyncSession,
    *,
    enabled: bool,
    base_url: str,
    owner_username: str | None,
    owner_password: str | None,
    fetch_connected_clients: bool,
    fetch_portal_logs: bool,
    request_timeout_seconds: int,
    verify_tls: bool,
) -> TplinkDecoConfig:
    config = await get_or_create_tplink_deco_config(db)
    config.enabled = enabled
    config.base_url = _normalize_base_url(base_url)
    config.owner_username = (owner_username or "").strip() or None
    config.owner_password = (owner_password or "").strip() or None
    config.fetch_connected_clients = fetch_connected_clients
    config.fetch_portal_logs = fetch_portal_logs
    config.request_timeout_seconds = max(3, request_timeout_seconds)
    config.verify_tls = verify_tls
    await db.flush()
    return config


async def _resolve_asset_for_client(db: AsyncSession, client: DecoClientRecord) -> Asset | None:
    resolver = AssetIdentityResolver(db, source="tplink_deco")
    return await resolver.resolve_asset(
        mac=client.mac,
        ip=client.ip,
        hostname=client.hostname or client.nickname,
        lookup_order=("mac", "ip", "hostname"),
    )


async def _resolve_asset_for_deco_device(db: AsyncSession, device: DecoDeviceRecord) -> Asset | None:
    resolver = AssetIdentityResolver(db, source="tplink_deco")
    return await resolver.resolve_asset(
        mac=device.mac,
        ip=device.ip,
        hostname=device.hostname or device.nickname,
        lookup_order=("mac", "ip", "hostname"),
    )


def func_lower(column):
    from sqlalchemy import func
    return func.lower(column)


async def _enrich_asset_from_client(db: AsyncSession, asset: Asset, client: DecoClientRecord) -> None:
    _set_asset_identity(asset, mac=client.mac, hostname=client.hostname)
    asset.custom_fields = _merge_custom_fields(
        asset.custom_fields,
        "tplink_deco",
        {
            "nickname": client.nickname,
            "device_model": client.device_model,
            "connection_type": client.connection_type,
            "access_point_name": client.access_point_name,
            "last_seen_via": "tplink_deco",
            "raw": client.raw,
        },
    )

    tag_names = await _existing_asset_tags(db, asset)
    _ensure_asset_tag(db, asset, "tplink-deco", tag_names)
    if client.connection_type and "wireless" in client.connection_type.lower():
        _ensure_asset_tag(db, asset, "wifi", tag_names)

    await record_passive_observation(
        db,
        asset=asset,
        source="tplink_deco",
        event_type="client_seen",
        summary=f"TP-Link Deco portal observed {client.hostname or client.nickname or client.ip or client.mac or asset.ip_address}",
        details={
            "ip": client.ip or asset.ip_address,
            "mac": client.mac or asset.mac_address,
            "hostname": client.hostname or client.nickname,
            "service_name": client.access_point_name,
            "device_model": client.device_model,
            "connection_type": client.connection_type,
            "raw": client.raw,
        },
    )


async def _upsert_deco_client_topology_link(
    db: AsyncSession,
    client_asset: Asset,
    client: DecoClientRecord,
    device_assets_by_name: dict[str, Asset],
) -> int:
    access_point_name = _deco_name_key(client.access_point_name)
    if not access_point_name:
        return 0
    if client.connection_type and "wireless" not in client.connection_type.lower():
        return 0
    access_point = device_assets_by_name.get(access_point_name)
    if access_point is None:
        result = await db.execute(select(Asset).where(func_lower(Asset.hostname) == access_point_name).limit(1))
        access_point = result.scalar_one_or_none()
    if access_point is None or access_point.id == client_asset.id:
        return 0

    segment = await ensure_segment_for_asset(db, access_point, source="tplink_deco")
    metadata = {
        "source": "tplink_deco",
        "relationship_type": "wireless_ap_for",
        "observed": True,
        "confidence": 0.92,
        "segment_id": segment.id if segment else None,
        "access_point_name": client.access_point_name,
        "client_mac": client.mac or client_asset.mac_address,
        "client_ip": client.ip or client_asset.ip_address,
        "connection_type": client.connection_type,
    }
    return await _upsert_topology_link(db, access_point.id, client_asset.id, "wifi", metadata)


async def _enrich_asset_from_deco_device(db: AsyncSession, asset: Asset, device: DecoDeviceRecord) -> None:
    _set_asset_identity(asset, mac=device.mac, hostname=device.hostname)
    asset.vendor = asset.vendor or "TP-Link"
    asset.custom_fields = _merge_custom_fields(
        asset.custom_fields,
        "tplink_deco_device",
        {
            "nickname": device.nickname,
            "model": device.model,
            "role": device.role,
            "software_version": device.software_version,
            "hardware_version": device.hardware_version,
            "last_seen_via": "tplink_deco",
            "raw": device.raw,
        },
    )

    tag_names = await _existing_asset_tags(db, asset)
    _ensure_asset_tag(db, asset, "tplink-deco", tag_names)
    _ensure_asset_tag(db, asset, "access-point", tag_names)

    await record_passive_observation(
        db,
        asset=asset,
        source="tplink_deco",
        event_type="deco_seen",
        summary=f"TP-Link Deco portal observed node {device.hostname or device.nickname or device.ip or device.mac or asset.ip_address}",
        details={
            "ip": device.ip or asset.ip_address,
            "mac": device.mac or asset.mac_address,
            "hostname": device.hostname or device.nickname,
            "model": device.model,
            "role": device.role,
            "software_version": device.software_version,
            "hardware_version": device.hardware_version,
            "raw": device.raw,
        },
    )


def _set_asset_identity(asset: Asset, *, mac: str | None, hostname: str | None) -> None:
    if mac and not asset.mac_address:
        asset.mac_address = mac
    if hostname and not asset.hostname:
        asset.hostname = hostname
    asset.status = "online"


def _merge_custom_fields(
    custom_fields: dict[str, Any] | None,
    key: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(custom_fields or {})
    merged[key] = payload
    return merged


async def _existing_asset_tags(db: AsyncSession, asset: Asset) -> set[str]:
    result = await db.execute(select(AssetTag).where(AssetTag.asset_id == asset.id))
    return {tag.tag for tag in result.scalars().all()}


def _ensure_asset_tag(db: AsyncSession, asset: Asset, tag: str, tag_names: set[str]) -> None:
    if tag in tag_names:
        return
    db.add(AssetTag(asset_id=asset.id, tag=tag))
    tag_names.add(tag)


async def test_tplink_deco_connection(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_tplink_deco_config(db)
    if not config.owner_password:
        raise ValueError("Set the TP-Link Deco owner password before testing the module.")
    async with TplinkDecoClient(
        base_url=config.base_url,
        owner_username=config.owner_username,
        owner_password=config.owner_password,
        timeout_seconds=config.request_timeout_seconds,
        verify_tls=config.verify_tls,
    ) as client:
        await client.login()
        devices = await client.fetch_deco_devices()
        clients: list[DecoClientRecord] = []
        if config.fetch_connected_clients:
            clients = await client.fetch_connected_clients()
        await client.logout()
    config.last_tested_at = _utcnow()
    config.last_status = "healthy"
    config.last_error = None
    config.last_client_count = len(clients)
    await db.flush()
    return {
        "status": "healthy",
        "client_count": len(clients),
        "device_count": len(devices),
        "base_url": config.base_url,
        "auth_username": _effective_owner_username(config.owner_username),
    }


async def sync_tplink_deco_module(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_tplink_deco_config(db)
    if not config.enabled:
        raise ValueError("Enable the TP-Link Deco module before syncing.")
    if not config.owner_password:
        raise ValueError("Set the TP-Link Deco owner password before syncing.")

    run = TplinkDecoSyncRun(status="running", started_at=_utcnow())
    db.add(run)
    await db.flush()

    try:
        devices, clients, logs_excerpt = await _fetch_tplink_sync_payload(config)
        logs_excerpt = _augment_logs_with_summary(logs_excerpt)
        log_analysis = analyze_deco_logs(logs_excerpt or "")
        ingested_assets = await _ingest_tplink_records(db, devices, clients)
        _finalize_tplink_sync_run(run, config, clients, logs_excerpt, log_analysis)
        await db.flush()
        return _serialize_tplink_sync_result(run, config, devices, clients, ingested_assets, log_analysis)
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = _utcnow()
        config.last_status = "error"
        config.last_error = str(exc)
        await db.flush()
        raise


def _parse_log_export_response(response: httpx.Response) -> str | None:
    if response.status_code != 200:
        return None
    content_type = (response.headers.get("content-type") or "").lower()
    text = response.text.strip()
    if not text:
        return None
    if "application/json" in content_type or text.startswith("{"):
        try:
            body = response.json()
        except Exception:
            return None
        if body.get("error_code") in (0, None):
            return json.dumps(body, indent=2)
        return None
    return text


async def _fetch_tplink_sync_payload(config: TplinkDecoConfig) -> tuple[list[DecoDeviceRecord], list[DecoClientRecord], str | None]:
    async with TplinkDecoClient(
        base_url=config.base_url,
        owner_username=config.owner_username,
        owner_password=config.owner_password,
        timeout_seconds=config.request_timeout_seconds,
        verify_tls=config.verify_tls,
    ) as client:
        await client.login()
        devices = await client.fetch_deco_devices()
        clients = await client.fetch_connected_clients() if config.fetch_connected_clients else []
        logs_excerpt = await client.fetch_portal_logs() if config.fetch_portal_logs else None
        await client.logout()
    return devices, clients, logs_excerpt


def _augment_logs_with_summary(logs_excerpt: str | None) -> str | None:
    if not logs_excerpt:
        return logs_excerpt
    parsed_summary = _parse_deco_log_summary(logs_excerpt)
    if not parsed_summary:
        return logs_excerpt
    return f"{parsed_summary}\n\n{logs_excerpt}"


async def _ingest_tplink_records(db: AsyncSession, devices: list[DecoDeviceRecord], clients: list[DecoClientRecord]) -> int:
    device_assets_by_name: dict[str, Asset] = {}
    for device_record in devices:
        asset = await _resolve_asset_for_deco_device(db, device_record)
        if asset is None:
            continue
        await _enrich_asset_from_deco_device(db, asset, device_record)
        for name in (device_record.hostname, device_record.nickname):
            name_key = _deco_name_key(name)
            if name_key:
                device_assets_by_name[name_key] = asset

    ingested_assets = 0
    for client_record in clients:
        asset = await _resolve_asset_for_client(db, client_record)
        if asset is None:
            continue
        await _enrich_asset_from_client(db, asset, client_record)
        await _upsert_deco_client_topology_link(db, asset, client_record, device_assets_by_name)
        ingested_assets += 1
    return ingested_assets


def _finalize_tplink_sync_run(
    run: TplinkDecoSyncRun,
    config: TplinkDecoConfig,
    clients: list[DecoClientRecord],
    logs_excerpt: str | None,
    log_analysis: dict[str, Any],
) -> None:
    run.status = "done"
    run.client_count = len(clients)
    run.clients_payload = [client.raw for client in clients]
    run.logs_excerpt = logs_excerpt or None
    run.log_analysis = log_analysis
    run.finished_at = _utcnow()
    config.last_sync_at = run.finished_at
    config.last_status = "healthy"
    config.last_error = None
    config.last_client_count = len(clients)


def _serialize_tplink_sync_result(
    run: TplinkDecoSyncRun,
    config: TplinkDecoConfig,
    devices: list[DecoDeviceRecord],
    clients: list[DecoClientRecord],
    ingested_assets: int,
    log_analysis: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": "done",
        "client_count": len(clients),
        "device_count": len(devices),
        "ingested_assets": ingested_assets,
        "log_excerpt_present": bool(run.logs_excerpt),
        "health_score": log_analysis.get("health_score"),
        "issue_count": len(log_analysis.get("issues", [])),
        "auth_username": _effective_owner_username(config.owner_username),
        "run_id": run.id,
    }


async def audit_tplink_config_change(db: AsyncSession, *, user: User, config: TplinkDecoConfig) -> None:
    await log_audit_event(
        db,
        action="module.tplink_deco.updated",
        user=user,
        target_type="tplink_deco_config",
        target_id=str(config.id),
        details={"enabled": config.enabled, "base_url": config.base_url},
    )
