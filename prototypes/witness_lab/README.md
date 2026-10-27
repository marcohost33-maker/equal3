# Witness lab: signed checkpoints, external witnesses and the NR-01 rollback (roadmap P0-3)

Not part of any research version and not wired into the anchor. This lab shows the mechanism that
roadmap P0-3 asks for and [docs/ADR-002](../../docs/ADR-002_checkpointed-audit-log.md) item 4
relies on. Signed checkpoints, cosigned by witnesses outside the local rollback domain, make a
**joint rollback of all local components detectable**. That is finding NR-01, which no local
mechanism of Equal3 could detect.

## What is implemented

From the C2SP editor's copies (github.com/C2SP/C2SP @ `fea9004`, fetched 2026-10-27):

| File | Spec | Content |
|---|---|---|
| `note.py` | signed-note, tlog-checkpoint, tlog-cosignature | strict note parsing (UTF-8, no control characters, canonical base64, key-name rules); key IDs; vkeys; Ed25519 log signatures (type 0x01); timestamped Ed25519 checkpoint cosignatures (type 0x04, `cosignature/v1` + `time <t>` + checkpoint text) |
| `witness.py` | tlog-witness `add-checkpoint` | 400 / 403 / 404 / 409 (`text/x.tlog.size` body) / 422 / 200; old-size check and persistence in one `BEGIN IMMEDIATE` transaction; rejected but validly signed requests kept as misbehaviour evidence |
| `http_witness.py` | tlog-witness HTTP | `POST /add-checkpoint`, `GET /<sha256(origin)>/checkpoint`; stdlib, 127.0.0.1 only |
| `lab_log.py` | — | log operator on the RFC 9162 tree of `../merkle_audit_log`; client policy: log signature **and** a quorum of witness cosignatures **and** consistency with the largest checkpoint accepted before |

## Results

`test_witness_lab.py`, 18 tests, run as root and non-root:

| Scenario | Outcome |
|---|---|
| spec example note and vkey (signed-note) | key ID `530d903a` and signature verify (known answer) |
| first checkpoint, growth with consistency proof, same-size re-cosign | 200 |
| stale old size / old > size / unknown origin / untrusted key / bad proof / > 63 proof lines | 409 `8\n` / 400 / 404 / 403 / 422 / 400; state unchanged |
| same size with another root; non-empty proof at old size 0 | 422 |
| two concurrent requests from the same old size (10 rounds) | always exactly one 200 and one 409; stored size = winner |
| **joint rollback of log, local witness DB and client state** to size 10 after the external witnesses saw 20, then a fork to 15 | local witness **cosigns the fork** (NR-01 reproduced); external witnesses answer **409** (`20`); a client that requires 2 external cosignatures cannot accept the fork; the external witness still holds 20 > 10, so the rollback is visible |
| fork extended past the witnessed size (old 20, proof from the fork) | 422, kept as evidence with a valid log signature over a conflicting root |
| one external witness rolled back as well | that witness cosigns the fork, the other refuses; quorum 1 accepts, **quorum 2 rejects** |
| client that already accepted size 20 | rejects a forked 25 and an older 10 (`RollbackDetected`) |
| witness as a separate process over HTTP | 200, 409 with `text/x.tlog.size`, monitoring GET returns log signature and witness cosignature |

**Mutation checks**, each run by hand against a copy of the code. All 8 mutants are killed:
- vkey split on every `+`;
- `BEGIN DEFERRED` instead of `IMMEDIATE`;
- old size accepted when smaller;
- consistency proof skipped;
- same-size root not compared;
- note accepted without a known signature;
- client quorum ignored;
- cosignature verified without the time line.

The HTTP test found a real bug before release: the base64 part of a vkey can contain `+`, so the
vkey must be split at the first two `+` only.

## What this does not show

- **Independence is an operational property, not a code property.** The external witnesses here run
  in the same machine and test process (one over HTTP in a separate process). Detection works only
  if the witnesses are operated by other parties, in another administrative domain, with their own
  keys and storage, and if the client actually requires their cosignatures.
- **Freshness.** A client that is itself rolled back and does not ask a witness accepts old state.
  The quorum must be checked on every acceptance, and the cosignature timestamps should be bounded.
  Timestamp checks are not implemented here.
- **Witness compromise.** With `f` compromised or rolled-back witnesses, a quorum of `f + 1` is
  needed. The lab shows f = 1.
- **Not integrated.** The anchor does not use this yet. Integration belongs to the research round
  that implements ADR-002, with its own audit. Release stays NO-GO.

Run: `python -m unittest -v prototypes/witness_lab/test_witness_lab.py` (needs `cryptography`).
