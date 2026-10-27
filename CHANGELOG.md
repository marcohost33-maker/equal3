# Changelog

All research versions keep the release decision **NO-GO**. Version history of the research itself:
[docs/AUDIT_HISTORY.md](docs/AUDIT_HISTORY.md) and the lineage table in the [README](README.md).

## [Unreleased] — repository tooling, research content unchanged

### Added
- `tools/run_test_groups.py` with tests: single source for the 12 test groups, one process group
  per group, 300 s hang limit (timeout and helper processes killed, counted as failure), fail-closed
  summary parsing, `--require-no-skips`, `--expect-total`, JSON evidence.
- `verification/2026-10-27_linux/`: Linux re-run from a byte-identical bundle reconstruction:
  430/430 as root with 0 skips, `anchor_wire` 10/10 (about 11 s each).

### Changed
- CI runs `anchor_wire` on every push/PR (was manual-only and never started) and adds a root job
  that must run all 430 tests with no skip, so the 4 separate-UID isolation tests run in CI for
  the first time. The release decision stays NO-GO.

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
