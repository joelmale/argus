# Fingerprinting Engine Plan

Target: build a state-of-the-art evidence-driven fingerprinting engine for Argus.

## Phase 1 — Foundation

Target: persist normalized fingerprint evidence and derive detected device type from evidence scoring rather than one-off direct assignments.

- [x] Add `asset_evidence` table for normalized fingerprint evidence
- [x] Add `probe_runs` table for latest probe snapshot details
- [x] Normalize current scan results into persisted evidence records
- [x] Persist latest probe outputs for each asset
- [x] Derive detected `device_type` from evidence scoring
- [x] Preserve existing precedence: `manual override > detected type > unknown`
- [x] Expose evidence and probe runs on asset API endpoints
- [x] Add focused tests for evidence persistence and evidence-derived classification

Notes:
- Phase 1 stores the latest fingerprint snapshot per asset by replacing previous evidence/probe rows on refresh.
- Phase 1 keeps vendor and OS persistence mostly aligned with the existing logic; the first hard cutover is `device_type`.

## Phase 2 — Anonymous Fingerprinting Expansion

- [ ] Expand HTTP/TLS/mDNS/UPnP normalization depth
- [ ] Add favicon hashing
- [ ] Add stronger TCP/IP stack evidence
- [ ] Expand homelab vendor/model signatures
- [ ] Add evidence/confidence panel in the UI

## Phase 3 — Passive Radar

- [ ] Add persistent passive observations model
- [ ] Merge ARP/DHCP/mDNS passive events into fingerprint evidence
- [ ] Add transient-device timeline views

## Phase 4 — LLM Enrichment

- [ ] Add Ollama-backed evidence synthesis layer
- [ ] Store LLM outputs as hypotheses with provenance
- [ ] Add prompt and confidence controls in settings

## Phase 5 — Internet Lookup

- [ ] Add opt-in external lookup settings
- [ ] Add allowlist, budgets, caching, and provenance
- [ ] Use lookups only for unresolved/low-confidence fingerprints

## Phase 6 — Risk and Lifecycle

- [ ] Normalize product/version/CPE extraction
- [ ] Add CVE/KEV correlation
- [ ] Add local lifecycle/EOL catalog support
