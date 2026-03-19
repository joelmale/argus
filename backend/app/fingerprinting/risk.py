from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AssetEvidence, Finding, LifecycleRecord


@dataclass(slots=True)
class NormalizedProduct:
    product: str
    version: str | None
    source: str
    cpe: str | None = None


_CATALOG_DIR = Path(__file__).with_name("catalogs")


def _load_catalog(filename: str) -> list[dict]:
    return json.loads((_CATALOG_DIR / filename).read_text(encoding="utf-8"))


def extract_normalized_products(evidence: list) -> list[NormalizedProduct]:
    products: list[NormalizedProduct] = []
    seen: set[tuple[str, str | None, str]] = set()

    for item in evidence:
        details = item.details or {}
        product = details.get("product")
        version = details.get("version")
        cpe = details.get("cpe")
        if product:
            normalized = str(product).strip().lower()
            key = (normalized, str(version) if version else None, item.source)
            if key not in seen:
                products.append(NormalizedProduct(normalized, str(version) if version else None, item.source, str(cpe) if cpe else None))
                seen.add(key)
        if isinstance(cpe, str) and cpe.startswith("cpe:/"):
            parts = cpe.split(":")
            if len(parts) >= 5:
                normalized = parts[3].replace("_", " ").lower()
                cpe_version = parts[4] or None
                key = (normalized, cpe_version, item.source)
                if key not in seen:
                    products.append(NormalizedProduct(normalized, cpe_version, item.source, cpe))
                    seen.add(key)
        if item.key == "detected_app":
            normalized = item.value.strip().lower()
            key = (normalized, None, item.source)
            if key not in seen:
                products.append(NormalizedProduct(normalized, None, item.source))
                seen.add(key)

    return products


def _matches(product: NormalizedProduct, rule: dict) -> bool:
    if product.product != str(rule.get("product", "")).lower():
        return False
    version_prefix = rule.get("version_prefix")
    if not version_prefix:
        return True
    return bool(product.version and product.version.startswith(str(version_prefix)))


async def refresh_risk_and_lifecycle(db: AsyncSession, asset: Asset, evidence: list[AssetEvidence]) -> None:
    await db.execute(delete(Finding).where(Finding.asset_id == asset.id, Finding.source_tool == "fingerprint_catalog"))
    await db.execute(delete(LifecycleRecord).where(LifecycleRecord.asset_id == asset.id))

    products = extract_normalized_products(evidence)
    if not products:
        return

    vuln_catalog = _load_catalog("vulnerability_catalog.json")
    lifecycle_catalog = _load_catalog("lifecycle_catalog.json")

    for product in products:
        for rule in vuln_catalog:
            if not _matches(product, rule):
                continue
            db.add(
                Finding(
                    asset_id=asset.id,
                    source_tool="fingerprint_catalog",
                    external_id=rule.get("cve"),
                    title=rule["title"],
                    description=rule.get("description"),
                    severity=rule.get("severity", "info"),
                    status="open",
                    cve=rule.get("cve"),
                    service=product.product,
                    finding_metadata={
                        "source": product.source,
                        "version": product.version,
                        "cpe": product.cpe,
                        "kev": rule.get("kev", False),
                        "reference": rule.get("reference"),
                    },
                )
            )
        for rule in lifecycle_catalog:
            if not _matches(product, rule):
                continue
            db.add(
                LifecycleRecord(
                    asset_id=asset.id,
                    product=product.product,
                    version=product.version,
                    support_status=rule["support_status"],
                    eol_date=rule.get("eol_date"),
                    reference=rule.get("reference"),
                    details={"source": product.source, "cpe": product.cpe},
                )
            )
