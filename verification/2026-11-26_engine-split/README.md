# 2026-11-26: ADR-003 implementation candidate (P0-2), measured

Subject: `prototypes/engine_split/` on top of `main` @ `1ced6f8`. No file under `research/`
changed; `tools/verify_provenance.py` passes (405 files). Release decision: **NO-GO**; no gate closed.

Environment: Linux container, Python 3.13.18, SQLite 3.53.1, cryptography 50.0.1 (not the
locked 46.0.4), run as root. Same maintenance channel; not an independent review.

| file | content | result |
|---|---|---|
| `closure_candidate.json` | `check_import_closure.py` on a flat copy of `research/*.py` + `eq3_*.py`, entry `eq3_writer_service`, `--forbid '*_lab' --forbid eq3_provision` | **PASS, 0 violations**, closure of 10 modules |
| `closure_v0715_same_tree.json` | same tree and options, entry `anchored_writer_v0715` (negative control) | FAIL, 5 violations (as in the 2026-11-18 baseline) |
| `runtime_witness_distribution.json` | `runtime_import_witness.py --deny` on the allowlist build (`DISTRIBUTION.txt`, 10 files) | PASS; the run loaded exactly the 10 modules of the static closure |
| `test_engine_split.log` | `python -B -W error::ResourceWarning -m unittest -v prototypes/engine_split/test_engine_split.py` (root, cryptography 50.0.1) | 32 tests OK, 0 skipped |
| `test_engine_split_root_crypto4604.log` | the same in a venv from `tools/requirements-ci.lock` (`--require-hashes`, cryptography 46.0.4), root, staged tree (CI root lane emulated) | 32 OK, 0 skipped |
| `test_engine_split_uid65534_crypto4604.log` | the same as UID 65534 (CI non-root lane emulated) | 32 OK, 1 skipped (the root-only boundary test) |
| `mutants.json` | `prototypes/engine_split/mutate_engine_split.py` | 25 of 25 killed |
| `bench_set_cost.json` | `prototypes/engine_split/bench_engine_split.py --repeat 9` (exploratory, one host, median) | 9 full-history verifications per SET + FINALIZE in both; candidate/research wall clock 1.01 / 1.04 / 1.00 at 0 / 200 / 1000 commits |

Reproduce from the repository root:

```sh
stage=$(mktemp -d); cp research/*.py prototypes/engine_split/eq3_*.py "$stage/"
python tools/check_import_closure.py --research-dir "$stage" --entry eq3_writer_service \
    --forbid '*_lab' --forbid eq3_provision
python -m unittest -v prototypes/engine_split/test_engine_split.py
python prototypes/engine_split/mutate_engine_split.py
```

## Negative first

- Before the change, `tools/check_import_closure.py` and `tools/runtime_import_witness.py` had no
  `--forbid`. The three new tool tests failed (argparse exit 2) and now pass. Without the option,
  the lab anchor could not be forbidden.
- `LegacyBypass.test_research_store_writes_without_anchor_intent` records that v0.7.22 commits with
  no anchor intent. The candidate tests next to it require that the same operation is refused
  before anything is written.
- M04 (request id not compared) survived the first test version. It is not equivalent: the
  anchor accepts an intent whose request id does not fit the proposal. The test now corrupts
  each of digest, request id and proposal hash separately, and M04 and M18 are killed.

## Independent read-only review of `3542e36` and the follow-up

A separate reviewer agent (same model family, so not a cross-family review) found:

| | finding | follow-up |
|---|---|---|
| F1 P2 | any code can mint `CommitCapability(engine, fake_anchor)`; the binding is caller discipline | AST test pins minting to engine and composition root (M22 killed); README states the limit |
| F2 P2 | an ABORT between the intent check and the write still committed (repro: `DIVERGENCE_HOLD`) | anchor re-read inside the write transaction; test red before (M19 killed) |
| F3 P2 | M05 was mislabelled (operator precedence) and not equivalent: a twin capability commits first, the outer call gets `already_committed` | test with the race; M05 rewritten and killed; no equivalent mutant left |
| F4 P2 | `adjudicate` dropped `evidence=`, which the attested anchors of v0.7.16+ need | forwarded as in research; test red before (M21 killed) |
| F5 P3 | closure "0 violations" does not cover a public `StateEngine` mutator | stated in the README; `EngineSurface` is the guard (M06) |
| F6 P3 | the capability trusted the anchor's own base check | the intent's base must equal the anchor position; test red before (M20 killed) |

The reviewer confirmed that `_parse_proposal`, `_verified_snapshot`, `_commit` and the on-disk
format match `research/state_store.py` without a weaker check. The only differences it found
are the removed v1/WAL paths and fault points, and the chain-tail check moved earlier inside
the same `BEGIN IMMEDIATE`.

## Second self-check pass (after the review)

Re-checked the delivered state instead of trusting it. Measured, validated or falsified:

| # | blind spot | evidence | result |
|---|---|---|---|
| S1 | cost of the split was never measured | `bench_set_cost.json`; first run: **10 vs 9** full-history verifications, ratio 1.35 at 1000 commits | fixed: the capability no longer calls `describe_proposal`; base and target digest are compared **inside** `_commit`'s write transaction on the values it writes (also removes a check-then-write window, the storage-side fence check Kleppmann describes). Now 9 vs 9, ratio about 1.0. New mutant M23 |
| S2 | "works with the v0.7.16+ attested anchors" was assumed after F4 (stub test only) | new `ResearchAnchors` test against `PersistentCASAnchor` and `EvidenceRequiredCASAnchor` with a real signed observation | **validated**: equal answers and tables; FINALIZE without evidence refused in both |
| S3 | the built-in `_sqlite3` errors were set aside as "environment" | python-build-standalone links SQLite statically (its technical notes), so it is a real deployment shape | fixed in the candidate (`eq3_runtime_evidence`): classified HOLD; negative-first test red on research; mutant M24 |
| S4 | root separate-UID test not ported | `RootBoundary` test; CI root lane step without skips | **added**; ran as root here |
| S5 | closure "0 violations" did not cover a `StateEngine` mutator (F5) | 1 tool test, red before (4 failing cases) | fixed: the tool table covers `StateEngine`; the baseline still matches |
| S6 | mutant M25 (coordinator ignores the proposal hash in diagnosis) survived | conflict scenario via the `fast` codec strategy | **test added**; both say `CONFLICT_HOLD`; M25 killed |
| S7 | PR #3 and PR #4 could conflict | `git merge-tree` | clean |
| S8 | the WAL gate thresholds could be outdated | sqlite.org news: fix in 3.51.3, backports 3.50.7 and 3.44.6, 3.52.0 withdrawn | **validated**, gate unchanged |
| S9 | CI could not run | both lanes emulated: hash-locked venv, root and UID 65534 | green; the real CI run is still open |
| S10 | the CI root-lane step was first written with `PIPESTATUS` under `sh` and an absolute unittest path | review of my own YAML | rewritten before it ran: `cd` plus a relative path, explicit exit codes |

## Research suite in this container (environment finding)

`tools/run_test_groups.py --expect-total 430` as root, research tree unchanged:

- 9 of 12 groups pass, including `writer` (21, separate-UID tests not skipped) and `anchor_wire` (28).
- `equal`, `store` and `runtime` have 5 errors, all with one cause:
  `runtime_evidence_v0710.runtime_inventory()` reads `_sqlite3.__file__`. In this container's
  Python, `_sqlite3` is built in and has no `__file__`, so the call raises `AttributeError`.
- The gate still fails closed: no approval results. But the exception is not the classified
  `RuntimeEvidenceError` that `runtime_gate_v0711` catches.
- CI (setup-python 3.13, extension module) is green on the identical `research/` tree.
- The research module stays unchanged (rule 1). The candidate's `eq3_runtime_evidence` classifies
  the case as a HOLD (S3). The research fix belongs in the next research round.

`tools/test_check_sqlite_runtime.py::test_real_child_without_uid_drop` fails here before and after
the change (no separately mapped libsqlite3; already noted on 2026-11-18); it passes in CI.
