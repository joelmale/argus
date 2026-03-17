from __future__ import annotations

from app.db.models import Asset


def list_integration_events() -> list[dict[str, object]]:
    return [
        {
            "event": "new_device",
            "source": "notifications",
            "description": "A newly discovered asset was added to inventory.",
            "example": {
                "event": "new_device",
                "data": {
                    "ip": "192.168.1.42",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "hostname": "lab-switch",
                    "device_class": "switch",
                },
            },
        },
        {
            "event": "devices_offline",
            "source": "notifications",
            "description": "One or more assets were marked offline.",
            "example": {
                "event": "devices_offline",
                "data": {
                    "devices": [
                        {"ip": "192.168.1.10", "hostname": "nas-1", "status": "offline"},
                    ],
                },
            },
        },
        {
            "event": "scan_progress",
            "source": "websocket",
            "description": "Real-time scan progress updates published during active scans.",
            "example": {
                "event": "scan_progress",
                "data": {"job_id": "scan-id", "stage": "ports", "progress": 0.5},
            },
        },
        {
            "event": "scan_complete",
            "source": "websocket",
            "description": "A scan has completed or failed.",
            "example": {
                "event": "scan_complete",
                "data": {"job_id": "scan-id", "status": "done"},
            },
        },
    ]


def build_home_assistant_entities(assets: list[Asset]) -> dict[str, object]:
    device_entities: list[dict[str, object]] = []
    for asset in sorted(assets, key=lambda item: item.hostname or item.ip_address):
        tags = sorted(tag.tag for tag in asset.tags)
        device_entities.append(
            {
                "unique_id": f"argus_asset_{asset.id}",
                "name": asset.hostname or asset.ip_address,
                "state": asset.status,
                "entity_type": "binary_sensor" if asset.status in {"online", "offline"} else "sensor",
                "device": {
                    "identifiers": [str(asset.id)],
                    "manufacturer": asset.vendor or "Unknown",
                    "model": asset.device_type or "unknown",
                    "name": asset.hostname or asset.ip_address,
                },
                "attributes": {
                    "ip_address": asset.ip_address,
                    "mac_address": asset.mac_address,
                    "os_name": asset.os_name,
                    "os_version": asset.os_version,
                    "device_type": asset.device_type,
                    "tags": tags,
                },
            }
        )

    online = sum(1 for asset in assets if asset.status == "online")
    offline = sum(1 for asset in assets if asset.status == "offline")
    summary_entities = [
        {
            "unique_id": "argus_assets_total",
            "name": "Argus Assets Total",
            "state": len(assets),
            "entity_type": "sensor",
            "attributes": {"online": online, "offline": offline},
        },
        {
            "unique_id": "argus_assets_online",
            "name": "Argus Assets Online",
            "state": online,
            "entity_type": "sensor",
            "attributes": {"total": len(assets)},
        },
    ]

    return {
        "entities": summary_entities + device_entities,
        "notes": [
            "This endpoint is a read-only export for Home Assistant style ingestion.",
            "Argus does not push Home Assistant discovery messages automatically in this phase.",
        ],
    }
