"""WebSocket endpoint — pushes real-time scan events to connected clients."""
import asyncio
import contextlib
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
import redis.asyncio as redis

from app.core.config import settings
from app.core.security import decode_token
from app.db.models import User
from app.db.session import AsyncSessionLocal

router = APIRouter()

REDIS_CHANNEL = "argus:events"


async def _send_heartbeats(websocket: WebSocket) -> None:
    while True:
        await asyncio.sleep(30)
        try:
            await websocket.send_json({"event": "heartbeat"})
        except (RuntimeError, WebSocketDisconnect):
            return


@router.websocket("/events")
async def websocket_events(websocket: WebSocket):
    """
    Clients connect here to receive live scan progress and new-device events.
    Auth: first message must be JSON {"type": "auth", "token": "<jwt>"}.
    Messages are JSON: { "event": "device_discovered" | "scan_progress" | "heartbeat", "data": {...} }
    """
    await websocket.accept()

    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
        auth_msg = json.loads(raw)
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Auth timeout")
        return

    token = auth_msg.get("token") if isinstance(auth_msg, dict) else None
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing token")
        return

    subject = decode_token(token)
    if not subject:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
        return

    async with AsyncSessionLocal() as db:
        user = await db.get(User, subject)
        if user is None or not user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User not found")
            return

    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(REDIS_CHANNEL)
    heartbeat_task = asyncio.create_task(_send_heartbeats(websocket))

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=5.0)
            if message and message["data"]:
                try:
                    await websocket.send_json(json.loads(message["data"]))
                except (RuntimeError, WebSocketDisconnect):
                    break
            await asyncio.sleep(0.1)
    except (RuntimeError, WebSocketDisconnect):
        pass
    finally:
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, RuntimeError, WebSocketDisconnect):
            await heartbeat_task
        await pubsub.unsubscribe(REDIS_CHANNEL)
        await pubsub.aclose()
        await redis_client.aclose()
