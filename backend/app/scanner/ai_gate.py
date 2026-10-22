"""Decide which hosts get an AI investigation, and how many at once.

An investigation is a multi-step tool-calling conversation with the model, so it is the most
expensive thing a scan does. Running it for every host on every scan kept a local CPU-bound
model busy around the clock. The gate skips:

- hosts with nothing to reason about: no open ports and no successful probe;
- hosts whose scan evidence is unchanged since their last analysis, until that analysis is
  older than AI_REINVESTIGATE_DAYS;

and lets at most AI_MAX_CONCURRENT_HOSTS investigations run at once (default 1: a local model
serves one request at a time, so parallel calls only queue and time out).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.scanner.models import HostScanResult

SKIP_NO_EVIDENCE = "no_evidence"
SKIP_UNCHANGED = "unchanged"

# Queue priorities (higher runs first). The heuristic's uncertainty adds up to 50 within a tier.
PRIORITY_ON_DEMAND = 1000.0
PRIORITY_NEW = 300.0
PRIORITY_CHANGED = 200.0
PRIORITY_STALE = 100.0


def has_ai_evidence(result: HostScanResult) -> bool:
    return bool(result.open_ports) or any(p.success for p in result.probes)


def ai_input_signature(result: HostScanResult) -> str:
    """Stable hash of the evidence an investigation would see. Excludes volatile probe payloads."""
    material = {
        "mac": (result.host.mac_address or "").lower(),
        "vendor": result.mac_vendor or "",
        "hostname": result.reverse_hostname or "",
        "os": result.os_fingerprint.os_name or "",
        "ports": sorted(
            (p.port, p.protocol, p.service or "", p.product or "", p.version or "")
            for p in result.open_ports
        ),
        "probes": sorted({(p.probe_type, p.target_port or 0) for p in result.probes if p.success}),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class AIGate:
    # ip -> (input signature of the last analysis, when it ran)
    prior: dict[str, tuple[str, datetime]] = field(default_factory=dict)
    reinvestigate_after: timedelta = timedelta(days=7)
    skip_no_evidence: bool = True
    max_concurrent: int = 1
    # Deferred: queue hosts for the AI worker instead of investigating inside the scan.
    deferred: bool = False
    candidates: dict[str, tuple[float, str]] = field(default_factory=dict)  # ip -> (priority, signature)
    _semaphore: asyncio.Semaphore | None = None

    @property
    def semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(max(1, self.max_concurrent))
        return self._semaphore

    def skip_reason(self, result: HostScanResult, signature: str, now: datetime | None = None) -> str | None:
        if self.skip_no_evidence and not has_ai_evidence(result):
            return SKIP_NO_EVIDENCE
        previous = self.prior.get(result.host.ip_address)
        if previous is not None:
            prev_signature, analyzed_at = previous
            now = now or datetime.now(timezone.utc)
            if analyzed_at.tzinfo is None:
                analyzed_at = analyzed_at.replace(tzinfo=timezone.utc)
            if prev_signature == signature and now - analyzed_at < self.reinvestigate_after:
                return SKIP_UNCHANGED
        return None

    def priority(self, result: HostScanResult, signature: str) -> float:
        """New hosts first, then hosts whose evidence changed, then stale re-checks; least certain first."""
        from app.scanner.stages.fingerprint import classify

        previous = self.prior.get(result.host.ip_address)
        if previous is None:
            base = PRIORITY_NEW
        elif previous[0] != signature:
            base = PRIORITY_CHANGED
        else:
            base = PRIORITY_STALE
        hint = classify(result.host, result.ports, result.os_fingerprint, result.mac_vendor)
        return base + round((1.0 - max(0.0, min(1.0, hint.confidence))) * 50, 2)
