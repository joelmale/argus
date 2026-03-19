"""
MAC OUI Vendor Lookup

The first 3 octets of a MAC address (OUI — Organizationally Unique Identifier)
are assigned by the IEEE to specific manufacturers. This gives us free device
classification hints: an OUI registered to "Synology Inc." is almost certainly
a Synology NAS even before we run a single port scan.

Uses the mac-vendor-lookup library which bundles the IEEE database locally —
no internet request required.
"""
from __future__ import annotations

import logging
import re

from app.fingerprinting.datasets import lookup_mac_vendor_from_dataset

log = logging.getLogger(__name__)

_lookup = None


def _get_lookup():
    global _lookup
    if _lookup is None:
        try:
            from mac_vendor_lookup import MacLookup
            _lookup = MacLookup()
            # Update database if needed (first run)
            try:
                _lookup.update_vendors()
            except Exception:
                pass  # Use bundled DB if update fails
        except ImportError:
            log.warning("mac-vendor-lookup not installed")
    return _lookup


def lookup(mac: str | None) -> str | None:
    """
    Return vendor name for a MAC address string.
    Handles various formats: AA:BB:CC:DD:EE:FF, AABBCCDDEEFF, AA-BB-CC-DD-EE-FF.
    Returns None if not found or mac is None.
    """
    if not mac:
        return None

    # Normalize to XX:XX:XX:XX:XX:XX
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) < 6:
        return None
    normalized = ":".join(clean[i:i+2] for i in range(0, 12, 2))

    dataset_hit = lookup_mac_vendor_from_dataset(normalized)
    if dataset_hit:
        return dataset_hit

    lkp = _get_lookup()
    if lkp is None:
        return None

    try:
        return lkp.lookup(normalized)
    except Exception:
        return None
