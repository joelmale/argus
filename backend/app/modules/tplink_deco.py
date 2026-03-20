from __future__ import annotations

import base64
import hashlib
import json
import re
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

DEFAULT_DECO_OWNER_USERNAME = "admin"


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
    ciphertext = key.encrypt(plaintext.encode("utf-8"), asym_padding.PKCS1v15())
    return ciphertext.hex().upper()


def _aes_encrypt_base64(key: str, iv: str, plaintext: str) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key.encode("utf-8")), modes.CBC(iv.encode("utf-8")))
    encryptor = cipher.encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize())


def _aes_decrypt_json(key: str, iv: str, payload: str) -> dict[str, Any]:
    cipher = Cipher(algorithms.AES(key.encode("utf-8")), modes.CBC(iv.encode("utf-8")))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(base64.b64decode(payload)) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(plaintext) + unpadder.finalize()
    return json.loads(data.decode("utf-8"))


def _rand16() -> str:
    return "".join(str(int.from_bytes(hashlib.sha256(f"{datetime.now().timestamp()}-{i}".encode()).digest()[:1], "big") % 10) for i in range(16))


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


def _parse_deco_log_summary(raw_text: str) -> str:
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not lines:
        return ""

    counters = {
        "wifi_client_associations": 0,
        "wifi_handshakes_completed": 0,
        "80211k_timeouts": 0,
        "steering_engine_errors": 0,
        "invalid_message_events": 0,
        "mesh_band_mismatch_events": 0,
    }
    client_macs: set[str] = set()

    for line in lines:
        upper = line.upper()
        if "AP-STA-CONNECTED" in upper or "ACTION\":\"ASSOCIATE" in upper or "ACTION:ASSOCIATE" in upper:
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
        for match in re.findall(r"(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}", upper):
            client_macs.add(match.replace("-", ":"))

    summary_lines = ["# Parsed Deco Log Summary"]
    for key, value in counters.items():
        if value:
            summary_lines.append(f"{key}: {value}")
    if client_macs:
        summary_lines.append(f"unique_macs_observed: {len(client_macs)}")
    if len(summary_lines) == 1:
        return ""
    return "\n".join(summary_lines)


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

    async def fetch_portal_logs(self) -> str | None:
        if not self.stok or not self.sysauth:
            await self.login()
        attempts = [
            ("GET", None),
            ("POST", {"operation": "read"}),
            ("POST", {"operation": "write"}),
        ]
        for method, payload in attempts:
            if method == "GET":
                response = await self._client.get(
                    f"/cgi-bin/luci/;stok={self.stok}/admin/log_export",
                    params={"form": "save_log"},
                    cookies={"sysauth": self.sysauth},
                    headers={"Referer": f"{self.base_url}/webpages/index.html"},
                )
            else:
                response = await self._client.post(
                    f"/cgi-bin/luci/;stok={self.stok}/admin/log_export",
                    params={"form": "save_log"},
                    data=payload,
                    cookies={"sysauth": self.sysauth},
                    headers={"Referer": f"{self.base_url}/webpages/index.html"},
                )
            if response.status_code != 200:
                continue
            content_type = response.headers.get("content-type", "")
            text = response.text
            if "application/json" in content_type or text.strip().startswith("{"):
                try:
                    body = response.json()
                    if body.get("error_code") not in (0, None):
                        continue
                    return json.dumps(body, indent=2)
                except Exception:
                    continue
            if text.strip():
                return text
        return None

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
    if client.mac:
        result = await db.execute(select(Asset).where(func_lower(Asset.mac_address) == client.mac.lower()).limit(1))
        asset = result.scalar_one_or_none()
        if asset is not None:
            return asset
    if client.ip:
        result = await db.execute(select(Asset).where(Asset.ip_address == client.ip).limit(1))
        asset = result.scalar_one_or_none()
        if asset is not None:
            return asset
    if not client.ip:
        return None
    asset = Asset(ip_address=client.ip, mac_address=client.mac, hostname=client.hostname or client.nickname, status="online")
    db.add(asset)
    await db.flush()
    return asset


async def _resolve_asset_for_deco_device(db: AsyncSession, device: DecoDeviceRecord) -> Asset | None:
    if device.mac:
        result = await db.execute(select(Asset).where(func_lower(Asset.mac_address) == device.mac.lower()).limit(1))
        asset = result.scalar_one_or_none()
        if asset is not None:
            return asset
    if device.ip:
        result = await db.execute(select(Asset).where(Asset.ip_address == device.ip).limit(1))
        asset = result.scalar_one_or_none()
        if asset is not None:
            return asset
    if not device.ip:
        return None
    asset = Asset(ip_address=device.ip, mac_address=device.mac, hostname=device.hostname or device.nickname, status="online")
    db.add(asset)
    await db.flush()
    return asset


def func_lower(column):
    from sqlalchemy import func
    return func.lower(column)


async def _enrich_asset_from_client(db: AsyncSession, asset: Asset, client: DecoClientRecord) -> None:
    if client.mac and not asset.mac_address:
        asset.mac_address = client.mac
    if client.hostname and not asset.hostname:
        asset.hostname = client.hostname
    asset.status = "online"
    current_custom_fields = dict(asset.custom_fields or {})
    current_custom_fields["tplink_deco"] = {
        "nickname": client.nickname,
        "device_model": client.device_model,
        "connection_type": client.connection_type,
        "access_point_name": client.access_point_name,
        "last_seen_via": "tplink_deco",
        "raw": client.raw,
    }
    asset.custom_fields = current_custom_fields

    tag_names = {tag.tag for tag in (await db.execute(select(AssetTag).where(AssetTag.asset_id == asset.id))).scalars().all()}
    if "tplink-deco" not in tag_names:
        db.add(AssetTag(asset_id=asset.id, tag="tplink-deco"))
    if client.connection_type and "wireless" in client.connection_type.lower() and "wifi" not in tag_names:
        db.add(AssetTag(asset_id=asset.id, tag="wifi"))

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


async def _enrich_asset_from_deco_device(db: AsyncSession, asset: Asset, device: DecoDeviceRecord) -> None:
    if device.mac and not asset.mac_address:
        asset.mac_address = device.mac
    if device.hostname and not asset.hostname:
        asset.hostname = device.hostname
    asset.status = "online"
    asset.vendor = asset.vendor or "TP-Link"
    current_custom_fields = dict(asset.custom_fields or {})
    current_custom_fields["tplink_deco_device"] = {
        "nickname": device.nickname,
        "model": device.model,
        "role": device.role,
        "software_version": device.software_version,
        "hardware_version": device.hardware_version,
        "last_seen_via": "tplink_deco",
        "raw": device.raw,
    }
    asset.custom_fields = current_custom_fields

    tag_names = {tag.tag for tag in (await db.execute(select(AssetTag).where(AssetTag.asset_id == asset.id))).scalars().all()}
    if "tplink-deco" not in tag_names:
        db.add(AssetTag(asset_id=asset.id, tag="tplink-deco"))
    if "access-point" not in tag_names:
        db.add(AssetTag(asset_id=asset.id, tag="access-point"))

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
            logs_excerpt = None
            if config.fetch_portal_logs:
                logs_excerpt = await client.fetch_portal_logs()
            await client.logout()

        if logs_excerpt:
            parsed_summary = _parse_deco_log_summary(logs_excerpt)
            if parsed_summary:
                logs_excerpt = f"{parsed_summary}\n\n{logs_excerpt}"

        for device_record in devices:
            asset = await _resolve_asset_for_deco_device(db, device_record)
            if asset is None:
                continue
            await _enrich_asset_from_deco_device(db, asset, device_record)

        ingested_assets = 0
        for client_record in clients:
            asset = await _resolve_asset_for_client(db, client_record)
            if asset is None:
                continue
            await _enrich_asset_from_client(db, asset, client_record)
            ingested_assets += 1

        run.status = "done"
        run.client_count = len(clients)
        run.clients_payload = [client.raw for client in clients]
        run.logs_excerpt = logs_excerpt[:12000] if logs_excerpt else None
        run.finished_at = _utcnow()

        config.last_sync_at = run.finished_at
        config.last_status = "healthy"
        config.last_error = None
        config.last_client_count = len(clients)
        await db.flush()
        return {
            "status": "done",
            "client_count": len(clients),
            "device_count": len(devices),
            "ingested_assets": ingested_assets,
            "log_excerpt_present": bool(run.logs_excerpt),
            "auth_username": _effective_owner_username(config.owner_username),
            "run_id": run.id,
        }
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = _utcnow()
        config.last_status = "error"
        config.last_error = str(exc)
        await db.flush()
        raise


async def audit_tplink_config_change(db: AsyncSession, *, user: User, config: TplinkDecoConfig) -> None:
    await log_audit_event(
        db,
        action="module.tplink_deco.updated",
        user=user,
        target_type="tplink_deco_config",
        target_id=str(config.id),
        details={"enabled": config.enabled, "base_url": config.base_url},
    )
