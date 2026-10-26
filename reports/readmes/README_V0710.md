# Equal3 0.7.10 – Authenticated Replay + Linked Runtime Evidence

**Research candidate / NO-GO** (25 October 2026). Based on v0.7.9; no original files changed in Google Drive/GitHub.

## Regression command

`PYTHONDONTWRITEBYTECODE=1 python -W error::ResourceWarning -m unittest discover -q`

Expected in supplied original environment: **219/219**. Requires Unix/Linux for some POSIX peercred integration tests. Never run against personal, health or production data.

## New safeguards

- `StateStore.receipt()` now requires a full, coherent authenticated receipt history; a bare mutable SQLite lookup is no longer trusted.
- `StateStore.apply()` verifies a *duplicate* request using the authenticated receipt chain on both the fast-read and post-CAS race path.
- V1 (`LEGACY_UNSEALED`) receipts cannot certify replay or a result; explicit migration required.
- `runtime_evidence_v0710.py` records the actual mapped `libsqlite3` shared object, SHA256, Linux device/inode and the SQLite source ID, rather than treating the separate `_sqlite3` Python extension hash as library provenance. Identity only, **not attestation**.

## Known limitations

- Historic verification costs O(N) and adds significant latency. See `EVIDENCE_V0710/v079_replay_baseline.csv` and `v0710_replay_hardened.csv`; all results are local synthetic medians with n=20, not production SLA.
- The tested SQLite 3.46.1 is NOT confirmed patched for the WAL reset bug, and a patched library was NOT installed here.
- Local SHA-256 manifest is not cryptographically signed; independent source and binary provenance required.
- The authority and writer remain on one host; a shared data/anchor rollback is not detected.
- The authority journal remains DELETE/EXTRA; StateStore still WAL/FULL.
- No power-cut/VFS tests, hardware keys, production isolation, encryption or independent audit.

## Components

`state_store.py` (patched), `runtime_evidence_v0710.py` (new), `release_preflight_v078.py` (metadata corrected), `test_v0710_security.py` (13 tests), `EVIDENCE_V0710/` (full regression, repeatable script, raw measurements, code diffs).
