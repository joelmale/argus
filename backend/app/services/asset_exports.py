from __future__ import annotations

import csv
import html
import json
import tempfile
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models import Asset, AssetHistory, ConfigBackupSnapshot, Finding, ScanJob
from app.exporters import build_inventory_snapshot, render_ansible_inventory, render_terraform_inventory
from app.services.scan_queue import enqueue_scan_job

EXPORT_CSV_JOB_TYPE = "export_csv"
EXPORT_ANSIBLE_JOB_TYPE = "export_ansible"
EXPORT_TERRAFORM_JOB_TYPE = "export_terraform"
EXPORT_INVENTORY_JSON_JOB_TYPE = "export_inventory_json"
EXPORT_REPORT_JSON_JOB_TYPE = "export_report_json"
EXPORT_REPORT_HTML_JOB_TYPE = "export_report_html"

EXPORT_JOB_FILENAMES = {
    EXPORT_CSV_JOB_TYPE: ("argus-assets.csv", "text/csv", ".csv"),
    EXPORT_ANSIBLE_JOB_TYPE: ("argus-inventory.ini", "text/plain", ".ini"),
    EXPORT_TERRAFORM_JOB_TYPE: ("argus-assets.tf.json", "application/json", ".json"),
    EXPORT_INVENTORY_JSON_JOB_TYPE: ("argus-inventory.json", "application/json", ".json"),
    EXPORT_REPORT_JSON_JOB_TYPE: ("argus-report.json", "application/json", ".json"),
    EXPORT_REPORT_HTML_JOB_TYPE: ("argus-report.html", "text/html", ".html"),
}


async def enqueue_asset_export_job(
    db: AsyncSession,
    *,
    export_type: str,
) -> tuple[ScanJob, bool]:
    filename, _media_type, _suffix = EXPORT_JOB_FILENAMES[export_type]
    job, should_start = await enqueue_scan_job(
        db,
        targets="inventory",
        scan_type=export_type,
        triggered_by="manual",
        result_summary={
            "stage": "queued",
            "message": f"Queued export job for {filename}",
            "export_type": export_type,
        },
    )
    return job, should_start


async def run_asset_export_job(db: AsyncSession, job: ScanJob, job_id: str) -> None:
    if job.scan_type not in EXPORT_JOB_FILENAMES:
        raise ValueError(f"Unsupported export job type: {job.scan_type}")

    filename, media_type, suffix = EXPORT_JOB_FILENAMES[job.scan_type]
    assets = await _load_export_assets(db)
    artifact_path = _export_artifact_path(job_id, suffix)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    if job.scan_type == EXPORT_CSV_JOB_TYPE:
        content = _render_csv_export(assets)
        artifact_path.write_text(content, encoding="utf-8")
    elif job.scan_type == EXPORT_ANSIBLE_JOB_TYPE:
        artifact_path.write_text(render_ansible_inventory(assets), encoding="utf-8")
    elif job.scan_type == EXPORT_TERRAFORM_JOB_TYPE:
        artifact_path.write_text(render_terraform_inventory(assets), encoding="utf-8")
    elif job.scan_type == EXPORT_INVENTORY_JSON_JOB_TYPE:
        artifact_path.write_text(json.dumps(build_inventory_snapshot(assets), indent=2, sort_keys=True), encoding="utf-8")
    elif job.scan_type == EXPORT_REPORT_JSON_JOB_TYPE:
        artifact_path.write_text(
            json.dumps(await _build_report_snapshot(db, assets), indent=2, sort_keys=True),
            encoding="utf-8",
        )
    else:
        artifact_path.write_text(await build_report_html_async(db, assets), encoding="utf-8")

    job.result_summary = {
        "stage": "done",
        "message": f"Export ready: {filename}",
        "filename": filename,
        "content_type": media_type,
        "artifact_path": str(artifact_path),
        "export_type": job.scan_type,
    }
    await db.commit()


def export_download_info(job: ScanJob) -> tuple[Path, str, str]:
    summary = job.result_summary or {}
    artifact_path = summary.get("artifact_path")
    filename = summary.get("filename")
    content_type = summary.get("content_type")
    if not artifact_path or not filename or not content_type:
        raise ValueError("Export job is missing download metadata")
    return Path(str(artifact_path)), str(filename), str(content_type)


async def _load_export_assets(db: AsyncSession) -> list[Asset]:
    result = await db.execute(
        select(Asset).options(
            selectinload(Asset.tags),
            selectinload(Asset.ports),
            selectinload(Asset.ai_analysis),
        )
    )
    return list(result.scalars().all())


def _render_csv_export(assets: list[Asset]) -> str:
    from io import StringIO

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "id",
        "ip_address",
        "hostname",
        "mac_address",
        "vendor",
        "os_name",
        "device_type",
        "status",
        "first_seen",
        "last_seen",
        "tags",
        "custom_fields",
    ])
    for asset in assets:
        writer.writerow(
            [
                str(asset.id),
                asset.ip_address,
                asset.hostname or "",
                asset.mac_address or "",
                asset.vendor or "",
                asset.os_name or "",
                asset.effective_device_type,
                asset.status,
                asset.first_seen.isoformat(),
                asset.last_seen.isoformat(),
                ",".join(sorted(tag.tag for tag in asset.tags)),
                asset.custom_fields or {},
            ]
        )
    return buffer.getvalue()


async def _build_report_snapshot(db: AsyncSession, assets: list[Asset]) -> dict[str, object]:
    open_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "open")) or 0
    total_findings = await db.scalar(select(func.count()).select_from(Finding)) or 0
    successful_backups = await db.scalar(
        select(func.count()).select_from(ConfigBackupSnapshot).where(ConfigBackupSnapshot.status == "done")
    ) or 0
    recent_changes_result = await db.execute(
        select(AssetHistory)
        .order_by(AssetHistory.changed_at.desc())
        .limit(10)
    )
    recent_changes = recent_changes_result.scalars().all()

    return {
        "summary": {
            "total_assets": len(assets),
            "online_assets": sum(1 for asset in assets if asset.status == "online"),
            "offline_assets": sum(1 for asset in assets if asset.status == "offline"),
            "total_findings": total_findings,
            "open_findings": open_findings,
            "successful_backups": successful_backups,
        },
        "recent_changes": [
            {
                "asset_id": str(change.asset_id),
                "change_type": change.change_type,
                "changed_at": change.changed_at.isoformat(),
                "diff": change.diff or {},
            }
            for change in recent_changes
        ],
        "inventory": build_inventory_snapshot(assets),
    }


async def build_report_html_async(db: AsyncSession, assets: list[Asset]) -> str:
    total = len(assets)
    online = sum(1 for asset in assets if asset.status == "online")
    offline = sum(1 for asset in assets if asset.status == "offline")
    open_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "open")) or 0
    successful_backups = await db.scalar(
        select(func.count()).select_from(ConfigBackupSnapshot).where(ConfigBackupSnapshot.status == "done")
    ) or 0

    rows = "".join(
        f"<tr><td>{html.escape(asset.ip_address)}</td><td>{html.escape(asset.hostname or '')}</td><td>{html.escape(asset.vendor or '')}</td><td>{html.escape(asset.effective_device_type)}</td><td>{html.escape(asset.status)}</td><td>{html.escape(', '.join(tag.tag for tag in asset.tags))}</td></tr>"
        for asset in assets
    )
    return f"""
        <html>
          <head>
            <title>Argus Inventory Report</title>
            <style>
              body {{ font-family: sans-serif; margin: 32px; color: #18181b; }}
              h1 {{ margin-bottom: 8px; }}
              .summary {{ display: flex; gap: 16px; margin: 16px 0 24px; }}
              .card {{ border: 1px solid #d4d4d8; border-radius: 12px; padding: 12px 16px; }}
              table {{ width: 100%; border-collapse: collapse; }}
              th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e4e4e7; font-size: 14px; }}
              th {{ background: #f4f4f5; }}
            </style>
          </head>
          <body>
            <h1>Argus Inventory Report</h1>
            <p>Generated from the current inventory snapshot.</p>
            <div class="summary">
              <div class="card"><strong>Total assets:</strong> {total}</div>
              <div class="card"><strong>Online:</strong> {online}</div>
              <div class="card"><strong>Offline:</strong> {offline}</div>
              <div class="card"><strong>Open findings:</strong> {open_findings}</div>
              <div class="card"><strong>Successful backups:</strong> {successful_backups}</div>
            </div>
            <table>
              <thead>
                <tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>Type</th><th>Status</th><th>Tags</th></tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </body>
        </html>
        """


def _export_artifact_path(job_id: str, suffix: str) -> Path:
    return Path(tempfile.gettempdir()) / "argus-exports" / f"{job_id}{suffix}"
