# === / Equal3 — Critical independent continuation audit v0.7.11
**Date:** 2026-10-25  |  **candidate:** v0.7.11 Research  |  **release:** NO-GO.

## 1. Verifiable source baseline

- Source ZIP: `EQUAL3_v0710_AUTHENTICATED_REPLAY_RUNTIME_EVIDENCE_2026-10-25.zip` (225,963 bytes), preserved original code as research baseline.
- Baseline suites in previous release reports: v0.7.10 = 219/219 tests, but not evidence of production readiness.
- Local interpreter: Python 3.13.5, built-in `_sqlite3` uses linked SQLite 3.46.1. The process library is identified through `/proc/self/maps`, shared object device+inode, not just Python extension name.
- Research question: eliminate unsigned/self-certified binary whitelist and establish an independently issuable signed runtime gate; prepare deterministic secure *offline* build that can later be run when an official source package is available.

## 2. Negative-first findings

**NR-0711-01: Unsigned approval trust confusion.** Prior `require_approved_sqlite(approved:dict)` could conceptually treat a dictionary supplied by its own caller as an independently approved source ID/hash. The old function warned that external authentication was needed, but its name and successful return value remained a potential promotion trap. **Fix:** it always fails now; the new signed-policy gate checks an out-of-band-pinned Ed25519 trust root and ties the authorization to deployment, ABI, architecture, actual shared library hash, source ID and short validity period.

**NR-0711-02: Read-hash path race.** Previous runtime inventory checked `stat(path)` and then independently reopened the path by `Path.read_bytes()`, which can race a file swap. **Fix:** O_NOFOLLOW, type/size and dev/inode checks on the *same opened descriptor*, SHA-256 streaming, fstat before/after, `/proc/self/maps` identity before/after. Under privileged attackers who can edit mapped bytes, this remains only evidence, not strong attestation.

**NR-0711-03: No available updated SQLite.** Official current SQLite release 3.54.1; installed SQLite 3.46.1. SQLite WAL-reset race affects unpatched versions from 3.7.0 to 3.51.2 under unusual simultaneous writer/checkpointer concurrency. Previous v0.7.9 DELETE/EXTRA anchor does not fix the WAL/FULL StateStore. No official 3.54.1 ZIP could be downloaded into this sandbox; **no patched library was compiled, installed or tested**. This is a known P0 blocker, not a completed fix.

**NR-0711-04: Self-referential signer risk.** A correctly signed policy is not externally trusted if the Writer controls the key, clock, or policy issuer. Trust root must be pinned by a different administrator; expiration and revocation/rollback still require external controls. A successful runtime signature check is only one security gate; explicit result `NO_GO_OTHER_P0_GATES`.

## 3. Implemented code

- `runtime_gate_v0711.py`: strictly sized Ed25519 signatures, raw-byte signature verification, duplicate-key rejection, exact schema, deployment binding, strong type/format checks, 30-day maximum time window, effective `.so` hash/source ID/ABI/architecture verification; returns NO_GO for whole product.
- `runtime_evidence_v0710.py`: safe O_NOFOLLOW/fstat library file inspection, mapped-file identity before and after, always-reject unsigned legacy allowlist.
- `check_sqlite_runtime_v0711.py`: CLI for externally issued signature and independently provisioned public key, bounded file reads with `O_NOFOLLOW`. Exits 2 on HOLD. Exit 0 signals this runtime *check* only, NOT production approval.
- `build_sqlite_v0711.py`: offline **recipe**, exact upstream ZIP SHA3-256, inner amalgamation C SHA3-256 and source ID validation, bounded extraction, isolated Linux shared library build, NEW interpreter smoke check against actually mapped library, evidence file. Source archive absent, so the happy path was NOT executed.
- `test_runtime_gate_v0711.py`, `test_sqlite_build_v0711.py`: 21 new tests including synthetic valid signature, invalid signatures, wrong library SHA, other deployment, malformed/duplicate keys, stale/future approvals, no symlink source, missing/invalid official ZIP, no overwrite of nonempty build directory, and real current-host mismatch.

## 4. Test and benchmark method

- Complete existing and new unittest suite with `-W error::ResourceWarning`, fresh temporary SQLite fixtures; coverage of user-facing crypto gate features only. Existing version claims remain separately scoped.
- 300 measured cryptographic gate operations on **synthetic** Ed25519 approval + **mock-patched** mapped SQLite runtime. Python 3.13.5 Linux x86_64, local CPU: 0.1349 ms median, 0.2677 ms p95. Excludes real SQLite runtime inventory, disk/network and process startup. **This is not a database benchmark** and cannot be compared to earlier WAL StateStore transaction latencies.
- Actual preflight: SQLite 3.46.1, `FAIL` for upstream WAL-reset, release verdict `NO_GO`; no signed production policy available.
- `EVIDENCE_V0711/` includes raw synthetic measurements, actual runtime inventory, preflight status, test logs.

## 5. Limitations and unclosed P0 gates

1. Source binary not fetched/build-tested; no patched library actually installed. Source SHA3 pins from upstream web are checksums, not a digitally signed chain of trust.
2. No trusted independent Ed25519 signer, revocation service, protected monotonic clock, and no signed production policy. Positive signature tests use ephemeral test keys and mocked facts.
3. Existing raw StateStore constructor/writer remains independently callable if filesystem/OS does not isolate it; the new CLI is *not* magically invoked on all raw calls. Application service integration and mandatory launch-time enforcement required.
4. No independent irreversible monotonic external anchor, no independent commit witness, no partition-fault or physical VFS/power-loss evidence.
5. No full at-rest encryption and lifecycle for DB/WAL/SHM/backups/temp, no production PII/DSG review, no independent security audit.
6. No production performance SLA; O(N) historical HMAC verification persists, with documented cost.
7. Other-platform loader/provenance, FIPS/cryptography dependencies, DDL/backwards compatibility and full replica lifecycle unverified.

## 6. Required next independent verification steps

- Obtain and independently validate `sqlite-amalgamation-3540100.zip`; compile in isolated reproducible build environment, validate original compiler flags and link target, verify *actual* mapped library under new Python process, then repeat all tests with strict WAL checkpoint concurrency.
- Issue a narrow signed policy from a key held independently of writer and state/anchor rollback domain; pin public key in read-only OS-managed configuration; enforce signed-policy verification in the only privileged writer service, with no bypass raw DB APIs.
- Add service-level release-board gate only after external anchor, isolated admin host, encryption, VFS powercut and independent review.

## 7. External technical references checked

- SQLite upstream: https://www.sqlite.org/wal.html (WAL-reset bug conditions and fixes).
- SQLite download listing: https://www.sqlite.org/download.html (3.54.1 amalgamation archive SHA3-256).
- SQLite release log: https://www.sqlite.org/releaselog/3_54_1.html (`sqlite3.c` SHA3-256 and `SQLITE_SOURCE_ID`).
- SQLite compiling guidance: https://www.sqlite.org/howtocompile.html .

**Decision: RESEARCH PASS FOR TESTED GATE; PRODUCTION NO-GO.** No changes were made to GitHub or user data. New Drive artifacts may be created only as research evidence.
