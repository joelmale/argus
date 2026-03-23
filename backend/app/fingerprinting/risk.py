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
        for candidate in _extract_item_products(item):
            _append_normalized_product(products, seen, candidate)

    return products


def _extract_item_products(item) -> list[NormalizedProduct]:
    details = item.details or {}
    product = details.get("product")
    version = _normalize_version(details.get("version"))
    cpe = _normalize_optional_text(details.get("cpe"))
    candidates: list[NormalizedProduct] = []

    if product:
        candidates.append(
            NormalizedProduct(
                product=_normalize_product_name(product),
                version=version,
                source=item.source,
                cpe=cpe,
            )
        )
    if cpe:
        cpe_candidate = _product_from_cpe(cpe, item.source)
        if cpe_candidate is not None:
            candidates.append(cpe_candidate)
    if item.key == "detected_app":
        candidates.append(
            NormalizedProduct(
                product=_normalize_product_name(item.value),
                version=None,
                source=item.source,
            )
        )
    return candidates


def _append_normalized_product(
    products: list[NormalizedProduct],
    seen: set[tuple[str, str | None, str]],
    product: NormalizedProduct,
) -> None:
    key = (product.product, product.version, product.source)
    if key in seen:
        return
    products.append(product)
    seen.add(key)


def _product_from_cpe(cpe: str, source: str) -> NormalizedProduct | None:
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    return NormalizedProduct(
        product=parts[3].replace("_", " ").lower(),
        version=parts[4] or None,
        source=source,
        cpe=cpe,
    )


def _normalize_product_name(value) -> str:
    return str(value).strip().lower()


def _normalize_version(value) -> str | None:
    return str(value) if value else None


def _normalize_optional_text(value) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


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
