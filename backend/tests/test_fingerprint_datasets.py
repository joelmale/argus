from __future__ import annotations

from pathlib import Path

from app.fingerprinting import datasets


def test_dataset_backed_mac_and_pen_lookups(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(datasets, "DATASET_DIR", tmp_path)
    datasets._clear_caches()

    (tmp_path / "wireshark_manuf.txt").write_text(
        "206D31\tFirewalla\n00155D\tMicrosoft\n",
        encoding="utf-8",
    )
    (tmp_path / "iana_pen.txt").write_text(
        "8072 NET-SNMP\n12325 Firewalla Inc.\n",
        encoding="utf-8",
    )

    assert datasets.lookup_mac_vendor_from_dataset("20:6D:31:41:56:2A") == "Firewalla"
    assert datasets.lookup_pen_vendor("1.3.6.1.4.1.12325.1.1") == "Firewalla Inc."
