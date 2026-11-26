# ADR-003 implementation candidate: engine without public mutators, cycle-free writer closure

Status: **prototype, not a research version, not operated, not reviewed by a third party.**
It sits next to the research tree. No file under `research/` changed, and it closes no release gate.
Release decision: **NO-GO**.

Roadmap item **P0-2**: restrict the production interface to the attested writer, exclude legacy
modules from the start path, adversarial bypass test. It implements decision items 1, 2 and 4 of
[ADR-003](../../docs/ADR-003_production-surface-legacy-bypass.md) and the acceptance tests
"import closure" and "distribution". It does not implement item 3, the OS policy for the writer
UID; see "Not shown" below.

## What it shows

| | research v0.7.22 (`anchored_writer_v0715`) | this candidate (`eq3_writer_service`) |
|---|---|---|
| import closure of the writer entry point | 11 modules, **5 violations**: 4 legacy mutators via `state_store`, one cycle of 6 modules | 10 modules, **0 violations**, no baseline |
| write without an anchor intent | `StateStore.apply(proposal)` commits; the anchor sees it only afterwards (`DIVERGENCE_HOLD`) | no public method writes; `CommitCapability.commit` refuses (`AnchorHold`) |
| what the commit is bound to | a validly signed proposal | the anchor's PREPARED intent: proposal hash, request id, store, base, base digest, target digest; the intent's base must equal the anchor position; the anchor is re-read inside the write transaction |
| master key | public attribute `StateStore.key` | not an attribute; signing and authenticated decoding are engine methods |
| unanchored service path | `WriterCore` behind `_research_unanchored=True` | none; `serve()` HOLDs unless an anchor object is passed |
| allowlist build | – | `DISTRIBUTION.txt`: 10 files; `state_store`, `anchor_protocol`, `anchor_wire`, `writer_service_v0714`, `store_cli`, the lab anchor and provisioning raise `ImportError` from it |

Measured on 2026-11-26 (Linux, Python 3.13.18, SQLite 3.53.1, root):
[verification/2026-11-26_engine-split](../../verification/2026-11-26_engine-split/README.md).

## Modules

| module | derived from (v0.7.22, unchanged there) | change |
|---|---|---|
| `eq3_anchor_types.py` | `anchor_protocol.py`: exceptions, dataclasses, review message | leaf module, so engine, coordinator and lab share them without a cycle |
| `eq3_engine.py` | `state_store.py` | `StateEngine`: read/verify side only; `_commit` (= `StateStore.apply`) reachable only through `CommitCapability`, minted by `bind_writer(path, key=, anchor=)`; DELETE journal and schema v2 only |
| `eq3_provision.py` | `StateStore.create` | genesis creation; **not** in the distribution, forbidden in the closure check |
| `eq3_coordinator.py` | `anchor_protocol.CoordinatedStore`, `position_for_genesis` | same assessment codes and HOLD rules; commits through the capability |
| `eq3_anchor_lab.py` | `anchor_protocol.MemoryCASAnchor` | volatile test double; **not** in the distribution, forbidden in the closure check |
| `eq3_anchored_writer.py` | `anchored_writer_v0715.py` | built from `(engine, capability, anchor)`; same `dispatch` answers |
| `eq3_wire.py` | `writer_service_v0714.py`: frame constants, reader, client | leaf; the service can import the anchored writer without a cycle |
| `eq3_wal_gate.py` | `anchor_wire.sqlite_wal_reset_safe` | leaf; in the research tree this import closes the 6-module cycle |
| `eq3_runtime_gate.py` | `runtime_gate_v0711.py` | byte-identical except that one import (pinned by a test) |
| `eq3_writer_service.py` | `writer_service_v0714.py` | without `WriterCore` and `_research_unanchored`; SET goes through the anchored core |

`equal3.py` (codec) and `runtime_evidence_v0710.py` are used unchanged from `research/`; both
are leaves.

## Tests

```sh
python -B -W error::ResourceWarning -m unittest -v prototypes/engine_split/test_engine_split.py   # 26 tests
python prototypes/engine_split/mutate_engine_split.py                                             # 22 hand mutants
```

- **LegacyBypass** (negative first): v0.7.22 commits without an anchor intent. The candidate
  refuses, each time before anything is written:
  - without an intent;
  - for a different proposal;
  - for an intent whose digest, request id or proposal hash does not fit;
  - for an intent not based on the anchor position;
  - when an ABORT lands between the intent check and the write.

  A second capability that commits the same intent first does not let the outer call report
  success, and `adjudicate` forwards `evidence`, as research does for the attested anchors.
- **EngineSurface**: the public surface is a reviewed read-only set; calling every public method
  leaves the database file byte-identical; the write primitive and the key are used only inside
  `eq3_engine` (AST check over the candidate sources).
- **Differential**: one genesis file, copied; the same 14 operations through research
  `AnchoredWriterCore` (v0.7.15) and through the candidate. This covers SET, HOLD while
  pending, review, replay, conflicting replay, malformed frames and an empty target. The
  answers are equal, and the four SQLite tables are equal row for row.
- **Faults**: an interruption after anchor PREPARE or after the SQLite commit gives the same HOLD
  state (`NOT_COMMITTED_HOLD` / `COMMITTED_PENDING_HOLD`) and the same recovery as research.
- **Compatibility**: research `StateStore` verifies and extends what the candidate wrote, and vice
  versa; WAL stores, wrong keys and a tampered receipt are refused.
- **Distribution**: allowlist build, static closure clean without a baseline (every listed file
  is needed), full-tree closure clean while research v0.7.15 stays red on the same tree, four
  mutants (legacy, lab, provisioning and cycle edges) turn it red, PEP 578 run-time witness clean
  with `--deny`, and legacy, lab and provisioning modules are not importable.
- **Service**: `serve()` HOLDs without an anchor; the RPC handler reaches the anchored core over a
  real AF_UNIX socket and refuses another peer UID.
- **Derivation**: the WAL gate equals the research function on 192 versions; the runtime gate is
  the research file with one import changed.

Mutation run: **22 of 22 killed**. An independent read-only review of the first version
(2026-11-26) found five issues, and each now has a test that was red before its fix:
- an ABORT racing the write (F2);
- a mislabelled mutant M05 that was not equivalent (F3);
- `evidence` dropped by `adjudicate` (F4);
- an intent base not checked against the anchor position (F6);
- capability minting not pinned (F1).

## Not shown (scope)

- **Not a boundary inside the process.** Same-process code can reach `engine._commit` or
  `engine._key`. It can also mint `CommitCapability(engine, fake_anchor)` with an anchor that
  reports whatever intent it likes, because the binding is only as good as the anchor object
  passed in.
  - The capability is a discipline, not an enforcement. The static closure check forbids
    introspection and dynamic imports, and an AST test pins which modules use the internals and
    where capabilities are minted (engine and composition root only).
  - The boundary stays the OS: a separate writer UID, key and DB 0600 (ADR-003 item 3), plus an
    authenticated anchor (P0-3).
- The in-transaction re-read of the anchor is meaningful only for an anchor whose pending intent
  cannot change between that read and the commit. A remote anchor needs a lease or fence on the
  intent (P0-3).
- "0 violations" in the closure check means no legacy module, no `StateStore` mutator and no
  cycle. The tool's legacy-API table names `StateStore` only. That `StateEngine` has no public
  mutator is shown by `EngineSurface`, not by the closure check.
- **ADR-003 item 3 is not implemented.** The adversarial same-UID test (systemd unit with
  `NoNewPrivileges` / `ProtectSystem`, no other code as the writer UID) needs a host with systemd.
- **No independent anchor.** The lab anchor is the v0.7.5 in-process test double. NR-01 (joint
  rollback) is untouched; that needs P0-3 (`prototypes/witness_lab`).
- **No new research version.** Adopting this needs a research round with its own manifest,
  evidence and an audit outside this channel (CONTRIBUTING rule 1).
- The root-only separate-UID tests of v0.7.14 were not rerun against the candidate service. The
  handler test uses a socketpair with the caller's UID.
