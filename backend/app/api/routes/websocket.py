"""WebSocket endpoint — pushes real-time scan events to connected clients."""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# Simple in-memory connection manager (scale with Redis pub/sub later)
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: dict):
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                self.active.remove(ws)


manager = ConnectionManager()


@router.websocket("/events")
async def websocket_events(websocket: WebSocket):
    """
    Clients connect here to receive live scan progress and new-device events.
    Messages are JSON: { "event": "device_discovered" | "scan_progress" | "heartbeat", "data": {...} }
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep alive — actual events pushed from scanner worker via manager.broadcast()
            await asyncio.sleep(30)
            await websocket.send_json({"event": "heartbeat"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
