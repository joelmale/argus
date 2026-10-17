from __future__ import annotations

import asyncio
import logging
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

import httpx

from app.core.config import settings

log = logging.getLogger(__name__)


async def notify_new_device(payload: dict, *, webhook: bool = True, email: bool = True) -> None:
    title = f"Argus new device: {payload.get('ip', 'unknown')}"
    tasks = []
    if webhook:
        tasks.append(_send_webhook({"event": "new_device", "data": payload}))
    if email:
        tasks.append(_send_email(title, _format_lines(payload)))
    if tasks:
        await asyncio.gather(*tasks)


async def notify_devices_offline(devices: list[dict], *, webhook: bool = True, email: bool = True) -> None:
    if not devices:
        return
    payload = {"event": "devices_offline", "data": {"devices": devices}}
    body = "\n\n".join(_format_lines(device) for device in devices)
    tasks = []
    if webhook:
        tasks.append(_send_webhook(payload))
    if email:
        tasks.append(_send_email(f"Argus offline devices: {len(devices)}", body))
    if tasks:
        await asyncio.gather(*tasks)


async def notify_ports_changed(data: dict, *, webhook: bool = True, email: bool = False) -> None:
    tasks = []
    if webhook:
        tasks.append(_send_webhook({"event": "ports_changed", "data": data}))
    if email:
        tasks.append(_send_email(f"Argus port changes: {data.get('ip', 'unknown')}", _format_lines(data)))
    if tasks:
        await asyncio.gather(*tasks)


async def notify_new_findings(data: dict, *, webhook: bool = True, email: bool = False) -> None:
    tasks = []
    if webhook:
        tasks.append(_send_webhook({"event": "new_findings", "data": data}))
    if email:
        body = "\n".join(f"[{item.get('severity')}] {item.get('title')}" for item in data.get("findings", []))
        tasks.append(_send_email(f"Argus new findings: {len(data.get('findings', []))}", body))
    if tasks:
        await asyncio.gather(*tasks)


async def _send_webhook(payload: dict) -> None:
    if not settings.NOTIFY_WEBHOOK_URL:
        return
    headers = {"Authorization": f"Bearer {settings.NOTIFY_WEBHOOK_TOKEN}"} if settings.NOTIFY_WEBHOOK_TOKEN else {}
    body = {**payload, "source": "argus", "sent_at": datetime.now(timezone.utc).isoformat()}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(settings.NOTIFY_WEBHOOK_URL, json=body, headers=headers)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        # A down receiver must never break a scan or ingest.
        log.warning("Webhook delivery failed for %s: %s", payload.get("event"), exc)


async def _send_email(subject: str, body: str) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_FROM or not settings.SMTP_TO:
        return
    await asyncio.to_thread(_send_email_sync, subject, body)


def smtp_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_FROM)


async def send_email_to(recipient: str, subject: str, body: str) -> None:
    """Send a one-off email to a specific recipient (e.g. password reset)."""
    if not smtp_configured():
        return
    await asyncio.to_thread(_send_email_sync, subject, body, recipient)


def _send_email_sync(subject: str, body: str, recipient: str | None = None) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.SMTP_FROM
    message["To"] = recipient or settings.SMTP_TO
    message.set_content(body)

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
        smtp.starttls()
        if settings.SMTP_USERNAME:
            smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        smtp.send_message(message)


def _format_lines(payload: dict) -> str:
    return "\n".join(f"{key}: {value}" for key, value in payload.items() if value not in (None, ""))
