# Changelog

All research versions keep the release decision **NO-GO**. Version history of the research itself:
[docs/AUDIT_HISTORY.md](docs/AUDIT_HISTORY.md) and the lineage table in the [README](README.md).

## [Unreleased] — repository tooling, research content unchanged

### Added
- `tools/run_test_groups.py` with tests: single source for the 12 test groups, one process group
  per group, 300 s hang limit (timeout and helper processes killed, counted as failure), fail-closed
  summary parsing, `--require-no-skips`, `--expect-total`, JSON evidence.
- `verification/2026-10-27_linux/`: Linux re-run from a byte-identical bundle reconstruction:
  430/430 as root with 0 skips, `anchor_wire` 10/10 (about 11 s each); tested hang hypotheses
  (`hang_hypotheses.json`).
- `tools/requirements-ci.lock`: hash lock of `cryptography==46.0.4` and its dependencies.
- Runner hardening after self-review: output to a temporary file instead of a pipe (a detached
  helper made a passing group block and report a timeout; negative-first test), `waitid(WNOWAIT)`
  before killing the process group (no PGID reuse), recorded skipped test ids and leftover helper
  processes, `--allow-skip`, `--expect-reported`, preflight for TMPDIR length (max 73, AF_UNIX)
  and, as root, paths reachable by UID 65534.

- P0-4: CI job that builds SQLite 3.54.1 from the official amalgamation with the unmodified research
  builder and runs all 430 tests as root on it (0 skips); `tools/check_sqlite_runtime.py` (+ tests)
  pins version, source id, mapped library path and SHA-256 and checks that the WAL-reset gate opens;
  negative control on the system SQLite (gate holds). Evidence: `verification/2026-10-27_sqlite-3.54.1/`.
- P1: `tools/bench_history_scaling.py` and `verification/2026-10-27_history-scaling/` (P50/P95/P99 of the
  O(n) audit digest and authenticated read at 1k/10k/100k; anchor HOLD at the 100k-row cap);
  `docs/ADR-002` (proposed RFC 9162 checkpointed log); `prototypes/merkle_audit_log/` (RFC 9162 tree,
  inclusion and consistency proofs, known-answer, exhaustive, tamper and mutation-checked tests).
- Runner: records the mapped libsqlite3 and source id, `--expect-sqlite`; as root the loaded library
  must be readable by other users (the loader otherwise falls back silently, measured).

### Changed
- CI runners pinned to ubuntu-24.04.
- CI runs `anchor_wire` on every push/PR (was manual-only and never started) and adds a root job
  that must run all 430 tests with no skip, so the 4 separate-UID isolation tests run in CI for
  the first time. The non-root job allows exactly those 4 skips by test id; both jobs check
  per-group counts, install dependencies hash-locked (wheels only) and upload their JSON
  evidence. The release decision stays NO-GO.

## [0.7.22-research] — repository assembled 2026-10-26

### Added
- Import of the v0.7.22 research bundle (`EQUAL3_v0722_REQUEST_LINEAGE_REAUDIT_2026-10-25.zip`,
  382 files) and of 23 Equal3 files from the 007acc2 review channel whose content is not in the
  bundle (2026-10-17 audits, transfer notes, fresh-zip rerun logs, v0.7.4 release gates).
  All byte-identical; paths reordered (see docs/PATH_MAPPING.md).
- `tools/verify_provenance.py` with tests: checks every imported file against the mapping table
  and the shipped `MANIFEST_V0722.sha256`, and rejects unmapped files.
- Documentation: README, docs/AUDIT_HISTORY.md, docs/ROADMAP.md, docs/THREAT_MODEL.md,
  docs/ADR-001, docs/PATH_MAPPING.md; LICENSE (Apache-2.0), CITATION.cff, SECURITY.md,
  CONTRIBUTING.md.
- CI on ubuntu-latest / Python 3.13: provenance check and the research test groups; the
  multi-process `anchor_wire` group only on manual dispatch.

### Research content of v0.7.22 (from the bundle, 2026-10-25)
- The guarded writer verifies that the receipt at the head version carries exactly the
  `request_id` stored in the signed commit witness; genesis requires a null request id.
- Negative-first test `test_commit_request_binding_v0722.py`; 29 focused tests reported passing;
  full suite not completed (`anchor_wire` timeout).
