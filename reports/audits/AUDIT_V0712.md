# === / Equal3 — Independent security regression audit v0.7.12

**Date:** 2026-10-25. **Base:** v0.7.11 Research, exact local unmodified original retained. **Decision:** RESEARCH CANDIDATE; **PRODUCTION NO-GO**.

## Scope and evidence provenance

This audit independently rechecks the previous v0.7.9–v0.7.11 reasoning, using the actual v0.7.11 source bundle rather than treating its previous narrative as proof. Baseline archive `EQUAL3_v0711_SIGNED_RUNTIME_GATE_OFFLINE_BUILDER_2026-10-25.zip` was available, with 152/152 entries in `MANIFEST_V0711.sha256` verified. Python 3.13.5 with linked SQLite 3.46.1 in this environment; SQLite 3.54.1 was **not installed or built**. No GitHub repository changes, no production credential access, and no production data were involved.

## Falsification 1: unauthenticated normal read

For a v2 store with one valid receipt, modify both `head.value` and `head.digest` offline to match SHA-256 of attacker-chosen content. Original v0.7.11 `StateStore.read()` **returned the forged content**, although `verify()` and `read_verified()` rejected it. Plain SHA-256 checks changes only, not authenticity. In v0.7.12 `StateStore.read()` calls `read_verified()` and refuses unsealed v1; corruption fails closed.

## Falsification 2: missing initial-state authentication

For a new v2 store with zero receipts, modify both `head.value` and `head.digest` offline. Original v0.7.11 `read()`, `verify()`, **and `read_verified()` all accepted** the forged state, even though `meta.genesis_digest` and its HMAC-protected tag committed to the original content. At version 0 the code did not compare current digest to the authenticated genesis. Fixed in v0.7.12; the genesis digest must match head digest on verified reads and before a successful write transaction.

## Falsification 3: legacy witness confidence

The `witness.state_checkpoint()` and `GuardedStore.read()` paths consumed a `verify()` report without rejecting `LEGACY_UNSEALED`, potentially producing `MATCH` on history with no authenticated receipt chain. The v0.7.12 witness and guarded readers reject this historical format rather than presenting it as authenticated. Migration must be independently attested, not re-label old rows.

## Code changes

- `state_store.py`: authenticated and coherent normal reads; verified genesis-to-head binding; before-write enforcement of v2, valid genesis MAC and head/last-receipt digest association.
- `witness.py` and `guarded_store.py`: reject legacy unsealed evidence.
- `test_v0712_integrity.py`: 10 negative/positive regressions on genesis, post-commit forged heads, existing signed proposal, legacy downgrade, witness startup, and failed writes.
- `test_anchor_protocol.py`, `test_v074_hardening.py`: correct obsolete assertions whose prior expectations treated a forged database as merely an anchor divergence or still allowed unverified raw reads; do not suppress old tests.

**Before/after evidence:** `EVIDENCE_V0712/falsification_results.json` runs the original and candidate in separate Python processes and pins each subprocess to its expected `state_store.py` absolute path. v0.7.11 accepted forged reads in both no-receipt and one-receipt examples; its zero-receipt *full audit also accepted*. All corresponding v0.7.12 checks refused them with `IntegrityError`.

**Regression:** `python -W error::ResourceWarning -m unittest discover -s . -p 'test_*.py' -q` => 250/250 PASS (71.794 seconds). Original reported v0.7.11 240/240; the original sources were not edited. Targeted legacy/guarded/protocol test sample: 72/72 PASS.

## Benchmark and testing caution

Benchmark source `EVIDENCE_V0712/benchmark_reads_v0712.py`, original vs candidate in *separate subprocesses*, each asserting the actual Python module file path. ABBA, 40 timed reads after 5 warmups, two per condition, same synthetic 1-KiB store history of 0, 50, or 250 commits. The first draft benchmark accidentally imported the candidate from both subprocesses because the working directory overrode `PYTHONPATH`. **Those draft results were discarded**; benchmark script corrected to set subprocess `cwd` and assert the absolute module path before measuring.

Final medians of paired run-medians (milliseconds), 0 / 50 / 250 receipts:

| receipts | v0.7.11 raw read | v0.7.12 verified read |
|---|---:|---:|
| 0 | 0.419 | 0.599 |
| 50 | 0.385 | 1.285 |
| 250 | 0.458 | 4.459 |

**Clearly a performance regression** with increasing history. Not a production workload, confidence interval, or throughput SLA. Rejecting forged data is a higher priority than preserving the old unsafe read speed. Cryptographically attested checkpoints must not permit skipping verification without an explicit trusted root and proof.

## Technical external verification and limits

- SQLite `PRAGMA integrity_check` checks database structure, format, indexes and constraints, **not a domain-specific HMAC chain**: https://www.sqlite.org/pragma.html.
- SQLite WAL-reset vulnerability: affected old versions, fixed in 3.51.3 and certain backports; the observed 3.46.1 Python-linked library remains a blocker: https://www.sqlite.org/wal.html.
- SQLite official 3.54.1 source/reference hashes: https://www.sqlite.org/download.html and https://www.sqlite.org/changes.html.
- OWASP recommends independent key administration and authenticated integrity mechanisms: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html.

## Still OPEN (mandatory P0 before production)

1. Actually download, verify SHA3, compile and load patched SQLite in a *new* Python runtime; prove provenance and concurrency safety with the full regression/fault lab. Signed policy module alone does not enforce the entry point for raw StateStore callers.
2. Mandatory exclusive writer with OS filesystem separation, immutable runtime approval, and externally pinned Ed25519 trust root; no raw bypass through a shared key or readable database permissions.
3. Independent non-rollbackable monotonic CAS anchor, external durable commit attestation, partition/replay/crash-gap recovery and joint rollback test.
4. Encryption/key management for DB + WAL + SHM + backups + temporary content, privacy impact assessment if real personal data, and independent security reviewer approval.
5. Actual powercut/VFS/ENOSPC/fsync fault-testing across hardware and OS and verified backup/restore durability.

**Final result:** The two new reproducible authenticity failures (including genesis at version zero) are repaired in the research candidate. Remaining P0 infrastructure and cryptographic trust controls are not closed; NO-GO is maintained. Package manifest is SHA-256 integrity only, not a digital signature or independent provenance proof.
