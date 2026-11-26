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
| `test_engine_split.log` | `python -B -W error::ResourceWarning -m unittest -v prototypes/engine_split/test_engine_split.py` | 26 tests OK |
| `mutants.json` | `prototypes/engine_split/mutate_engine_split.py` | 22 of 22 killed |

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

## Research suite in this container (environment finding)

`tools/run_test_groups.py --expect-total 430` as root, research tree unchanged:

- 9 of 12 groups pass, including `writer` (21, separate-UID tests not skipped) and `anchor_wire` (28).
- `equal`, `store` and `runtime` have 5 errors, all with one cause:
  `runtime_evidence_v0710.runtime_inventory()` reads `_sqlite3.__file__`. In this container's
  Python, `_sqlite3` is built in and has no `__file__`, so the call raises `AttributeError`.
- The gate still fails closed: no approval results. But the exception is not the classified
  `RuntimeEvidenceError` that `runtime_gate_v0711` catches.
- CI (setup-python 3.13, extension module) is green on the identical `research/` tree.
- Recorded as a P3 portability note for the next research round. The candidate copies the
  runtime gate unchanged and inherits the same behaviour.

`tools/test_check_sqlite_runtime.py::test_real_child_without_uid_drop` fails here before and after
the change (no separately mapped libsqlite3; already noted on 2026-11-18); it passes in CI.
