from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage

import httpx

from app.core.config import settings


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


async def _send_webhook(payload: dict) -> None:
    if not settings.NOTIFY_WEBHOOK_URL:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(settings.NOTIFY_WEBHOOK_URL, json=payload)


async def _send_email(subject: str, body: str) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_FROM or not settings.SMTP_TO:
        return
    await asyncio.to_thread(_send_email_sync, subject, body)


def _send_email_sync(subject: str, body: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.SMTP_FROM
    message["To"] = settings.SMTP_TO
    message.set_content(body)

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
        smtp.starttls()
        if settings.SMTP_USERNAME:
            smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        smtp.send_message(message)


def _format_lines(payload: dict) -> str:
    return "\n".join(f"{key}: {value}" for key, value in payload.items() if value not in (None, ""))
