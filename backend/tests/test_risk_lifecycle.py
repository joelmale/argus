from __future__ import annotations

from app.fingerprinting.evidence import EvidenceItem
from app.fingerprinting.risk import extract_normalized_products


def test_extract_normalized_products_uses_product_and_cpe():
    evidence = [
        EvidenceItem(
            source="nmap_service",
            category="service",
            key="443/tcp",
            value="https",
            confidence=0.8,
            details={"product": "OpenSSL", "version": "1.0.1f", "cpe": "cpe:/a:openssl:openssl:1.0.1f"},
        ),
        EvidenceItem(
            source="probe_http",
            category="identity",
            key="detected_app",
            value="Proxmox Virtual Environment",
            confidence=0.86,
            details={},
        ),
    ]

    products = extract_normalized_products(evidence)
    values = {(item.product, item.version) for item in products}

    assert ("openssl", "1.0.1f") in values
    assert ("proxmox virtual environment", None) in values
