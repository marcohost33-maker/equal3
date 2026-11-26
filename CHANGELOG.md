# Changelog

All research versions keep the release decision **NO-GO**. Version history of the research itself:
[docs/AUDIT_HISTORY.md](docs/AUDIT_HISTORY.md) and the lineage table in the [README](README.md).

## [Unreleased] — repository tooling, research content unchanged

### Added (2026-11-26)
- P0-2, ADR-003 implementation candidate: `prototypes/engine_split/`, a prototype next to the
  research tree; no research file changed.
  - `eq3_engine.StateEngine` has no public mutator. Its write primitive is reachable only
    through `CommitCapability`, which commits exactly the proposal of the anchor's PREPARED
    intent. All intent fields are compared before the write. The key is not an attribute.
  - Genesis creation (`eq3_provision`) and the in-process anchor double (`eq3_anchor_lab`) are
    outside the writer distribution.
  - Leaves `eq3_wal_gate` and `eq3_wire` remove the six-module cycle.
  - The writer entry point `eq3_writer_service` passes `check_import_closure.py` without a
    baseline: 10 modules, 0 violations. v0.7.15 on the same tree: 5.
  - 22 tests: negative first against the v0.7.22 bypass; a differential against v0.7.15
    (answers and tables equal); fault points; compatibility in both directions; allowlist build
    with a PEP 578 witness and `ImportError` for legacy, lab and provisioning modules; the RPC
    handler; derivation pins.
  - Mutation run: 17 of 18 killed, 1 equivalent.
  - Evidence: `verification/2026-11-26_engine-split/`. CI runs the tests and the full-tree
    closure in the non-root job.
- `--forbid PATTERN` (repeatable) for `tools/check_import_closure.py` and
  `tools/runtime_import_witness.py`. It adds forbidden module patterns to the defaults. Three
  negative-first tests, red on the unchanged tools (argparse exit 2). The tool tests now count
  30 (closure) and 10 (run-time witness).

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

- After the GPT-6 cross-family review: `check_sqlite_runtime.py --check-child-uid` (a child dropped
  to UID 65534 must map the same libsqlite3 as the parent; both root jobs); runner evidence records
  `GITHUB_SHA` (merge commit on pull requests) and the PR head SHA, ref and run id; ADR-002 states
  that a local seal gives no anti-rewrite protection without an external checkpoint and that the
  audit interval must be derived from RPO/RTO and the threat model; benchmarks labelled exploratory.

- P0-3 mechanism: `prototypes/witness_lab/`, covering C2SP signed-note, tlog-checkpoint,
  tlog-cosignature (Ed25519, timestamped) and the tlog-witness `add-checkpoint` protocol with atomic
  state, misbehaviour evidence and an HTTP front end. 33 tests:
  - spec known answer (vkey `530d903a`);
  - all status codes and a concurrency race;
  - NR-01 joint-rollback lab, witness rollback with quorum, fork evidence;
  - a separate-process HTTP witness;
  - HTTP request framing (RFC 9112 section 6) and connection reuse (sections 9.3 and 9.6).
  Seventeen mutants were killed by hand, five more for the R12 connection close by
  `diskriminierung.py` (one further mutant is equivalent on CPython 3.14). The HTTP test found a vkey parsing bug, fixed with a
  regression test. Runs in the non-root CI job.

- P0-2, first ADR-003 acceptance test (2026-11-18): `tools/check_import_closure.py` (+ 23 tests).
  Static (AST) import closure of the writer entry point `anchored_writer_v0715`; reports reachable
  legacy modules, the legacy write API (`StateStore.create/apply/checkpoint/backup_verified`),
  import cycles, and dynamic imports or file loaders it cannot resolve (fail closed). Red on the
  v0.7.22 tree as ADR-003 requires (5 violations). CI compares against
  `verification/2026-11-18_import-closure/baseline.json`: a new violation fails, and so does an
  improvement that was not recorded. 22 hand-made mutants of the tool are killed by its tests.
- P0-2, run-time complement (2026-11-21, cross-family review A7-R8): `tools/runtime_import_witness.py`
  (+ 9 tests). Imports the entry modules in a child interpreter under a PEP 578 audit hook
  (`import` and `open` events) and fails when a first-party module is loaded that the static
  closure does not contain or whose name is forbidden; `--deny` also raises in the child. Ten
  bypass routes are covered, five of which the static check cannot see by design (exec of
  base64 / compiled source, string annotations, pickle, executing a source file). A witness of
  one run, not a sandbox; the scope of the static check is now stated in ADR-003 as a structure
  contract for the project's own code.
- P0-3, cosignature freshness in the witness lab (2026-11-18): `lab_log.Freshness` and the
  `freshness` argument of `accept_checkpoint`. Only cosignatures with a timestamp inside
  `[now - max_age, now + max_future]` (both inclusive) count towards the quorum; otherwise
  `StaleCosignatures`. Six tests, written first and failing on `7d104ea` (the names did not exist;
  the first assertion of the replay test documents that the unchanged client accepts the replayed
  checkpoint). 15 mutants killed, one equivalent mutant recorded. The lab now has 39 tests.

### Changed (2026-11-18)
- `docs/ADR-003`: the import cycle has six modules, not four; it includes `writer_service_v0714`
  and `runtime_gate_v0711`. Found by the new check, verified in the sources.

### Fixed
- `prototypes/witness_lab/http_witness.py` request framing, reported by the cross-family review
  R3/R5 (P1). `int(Content-Length or 0)` accepted `+5` and `5_0`, raised an unhandled `ValueError`
  on non-numeric values, used the first of duplicate headers, ignored `Transfer-Encoding`, and
  passed a truncated body to the witness. Now: exactly one Content-Length of ASCII digits, no
  Transfer-Encoding (400 together with Content-Length, else 501), 411 / 413 / 400 for a missing,
  oversized or incomplete body, 408 after a socket timeout, connection closed on every framing
  error. Nine negative-first tests were red on the unchanged server (14 failing cases) and are green
  after the fix; eight mutants of the fix are killed.
- `http_witness.py` connection reuse, reported by the cross-family reviews R5/R9/R10 (latent: the
  server speaks HTTP/1.0). With HTTP/1.1 keep-alive enabled, a 404 for a wrong path left the request
  body unread and the server parsed it as a second request (two responses). Every error response
  (>= 400) now sends `Connection: close` and closes the connection (RFC 9112 section 9.3). Two tests:
  red on `a7c6e50` (3 failing cases), green after the fix; one mutant killed.
- `http_witness.py` connection reuse after a 200, reported by the cross-family review R12. On
  `8c22517` HTTP/1.1 still served a pipelined request after POST 200 and GET 200 (it reached the
  witness), and HTTP/1.0 sent no `Connection: close` with a 200. Every response now sets
  `close_connection` and sends `Connection: close` (RFC 9112 sections 9.3 and 9.6), so the lab
  serves one request per connection. New test over 16 request paths under HTTP/1.0 and HTTP/1.1
  with a pipelined canary: red on `8c22517` (8 failing cases), green after the fix. The earlier
  check that keep-alive still answers two pipelined well-formed requests contradicts this and is
  inverted. Green on Windows, on Linux as root and non-root, and in CI run 40931419436.
- `witness.py` stored note, reported by the Codex review of `5e1828d` (P2). A same-size
  resubmission of the public checkpoint with an extra signature line forged under the witness's own
  name and key ID was stored and served by the monitoring GET, so the served note no longer
  verified. The witness now stores only the checkpoint text and the log signature lines it verified.
  Test red on `5e1828d`, green after; the mutant without the filter is killed.

- P0-2 analysis: `docs/ADR-003` (proposed). Measured import graph: every service path imports
  `state_store` (legacy API), and there is an import cycle among the anchor modules. No production
  path exists today; the OS boundary is the current enforcement. The ADR proposes an engine/legacy
  split, a writer capability, an allowlist distribution with an import-closure check, and OS policy,
  with negative-first acceptance tests.

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
