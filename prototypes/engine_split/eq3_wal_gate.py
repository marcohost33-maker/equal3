"""ADR-003 candidate (prototype): SQLite WAL-reset version gate as a leaf module.

Copied without change from research/anchor_wire.py sqlite_wal_reset_safe (v0.7.22). In the
research tree runtime_gate_v0711 imports this function from anchor_wire, which closes the
six-module import cycle (anchor_wire -> writer_service_v0714 -> runtime_gate_v0711 ->
anchor_wire). As a leaf it has no first-party imports (ADR-003 item 4). Release: NO-GO.
"""
from __future__ import annotations

import sqlite3


def sqlite_wal_reset_safe(version=None):
    version = sqlite3.sqlite_version_info if version is None else tuple(version)
    # 3.52.0 was withdrawn for compatibility defects; never endorse as a release.
    if version[:2] == (3, 52):
        return False
    return (version >= (3, 51, 3) or (version[:2] == (3, 50) and version >= (3, 50, 7))
            or (version[:2] == (3, 44) and version >= (3, 44, 6)))
