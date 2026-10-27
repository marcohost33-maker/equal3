# Roadmap and release gates (state of v0.7.22)

Source: [`reports/roadmaps/ROADMAP_V0722.md`](../reports/roadmaps/ROADMAP_V0722.md),
[`reports/release-gates/RELEASE_GATES_V0722.json`](../reports/release-gates/RELEASE_GATES_V0722.json)
and the exit criteria G0–G6 of
[`reports/audits/AUDIT_GESAMT_V0721_2026-10-25.md`](../reports/audits/AUDIT_GESAMT_V0721_2026-10-25.md)
§9. Translated from German; the originals are authoritative.

The v0.7.22 roadmap ends with: *"Status: NO-GO. Keine Produktion und kein GitHub-Push."*
("No production and no GitHub push.") The owner later decided to publish the material as a
research record; that decision does not change the NO-GO status and does not create a release
(see [ADR-001](ADR-001_research-publication-without-release.md)).

## Prioritised roadmap (v0.7.22)

| ID | Item |
|---|---|
| P0-1 | Keep the security test `same value + different request_id` permanently in independent CI; stabilise the complete `anchor_wire` suite and deliver the 430-test regression from a fresh package. |
| P0-2 | Restrict the production interface to the attested writer, enforce OS access rights (separate UID), exclude all legacy modules from the production start path; adversarial bypass test. |
| P0-3 | Independently operated monotonic witness/trust register, replay and fork gossip protocol, signed checkpoints, inclusion/consistency proofs and rollback lab tests. |
| P0-4 | Officially patched SQLite binary with independent signature/build evidence in the actual Python process; complete new regression. |
| P0-5 | End-to-end observer fencing, crash recovery and durable commit proof at a real separate identity; offline/timeout partition tests. |
| P0-6 | KMS/HSM, data-protection inventory / Swiss FADP (CH-DSG), complete encryption at rest including backups, log privacy, VFS/power-loss lab. |
| P1 | Runtime cost of the O(n) historical audit; authenticated checkpoints with adversarial proof tests; P50/P95/P99 at 10k/100k history. |

### Status notes after the import (not part of the v0.7.22 roadmap)

- **P0-1, 2026-10-27, partly addressed.** The negative-first request-binding test runs in CI on every
  push/PR (it did since the import); `anchor_wire` now runs there too, and a root job runs the
  separate-UID tests. The 430-test regression from a byte-identical reconstruction of the bundle
  passed on Linux ([verification/2026-10-27_linux](../verification/2026-10-27_linux/README.md)).
  Still open: why `anchor_wire` hung in the audit environment, and a run by someone outside
  this channel ("independent CI" in the sense of the audits).
- **P0-4, 2026-10-27, partly addressed.** CI builds SQLite 3.54.1 from the official amalgamation with
  the unmodified research builder (SHA3 pins, also listed by sqlite.org). It shows that the test
  processes map exactly that library, and runs the full regression on it: 430/430 as root, 0 skips.
  The WAL-reset gate opens without override there and holds on the unpatched system SQLite
  ([verification/2026-10-27_sqlite-3.54.1](../verification/2026-10-27_sqlite-3.54.1/README.md)).
  Still open: signed/independently reproduced build evidence and a real deployment.
- **P1, 2026-10-27, measured and designed, not implemented.**
  - P50/P95/P99 at 1k/10k/100k: an anchor operation takes about 0.9 s at the 100k-row cap, after
    which the anchor HOLDs; an authenticated read takes about 1.7 s at 100k commits
    ([verification/2026-10-27_history-scaling](../verification/2026-10-27_history-scaling/README.md)).
  - Proposed fix: RFC 9162 checkpointed log ([ADR-002](ADR-002_checkpointed-audit-log.md)), with a
    tested prototype in `prototypes/merkle_audit_log/`.
  - Implementation needs its own research round.
- **P0-3, 2026-10-27, mechanism prototyped, not operated.** `prototypes/witness_lab/` implements C2SP
  signed checkpoints, Ed25519 checkpoint cosignatures and the tlog-witness `add-checkpoint` protocol
  (atomic state, misbehaviour evidence). Its lab tests reproduce NR-01 (a joint local rollback is
  cosigned by the restored local witness) and show the detection by external witnesses (409,
  quorum, newer checkpoint visible). Still open:
  - independently operated witnesses in another administrative domain;
  - gossip between clients and monitors;
  - timestamp/freshness policy;
  - integration into the anchor (research round).
- P0-2, P0-5 and P0-6 are unchanged and open.

## Release gates (RELEASE_GATES_V0722.json)

| Field | Value |
|---|---|
| version | `0.7.22-research` |
| release | `NO_GO` |
| date | 2026-10-25 |
| local_request_lineage_invariant | PASS: negative-first source-pinned fork test |
| focused_29_tests | PASS |
| full_legacy_suite | INCOMPLETE: anchor_wire multiprocess timeout |

Open P0 gates (`p0_open`):

| Gate | Meaning (editorial gloss derived from the roadmap above, not part of the JSON) |
|---|---|
| `independent_monotone_witness` | a witness outside the rollback domain of store, anchor and commit witness |
| `legacy_bypass_elimination` | no importable research/legacy write path in a production package |
| `patched_sqlite_runtime` | patched, attested SQLite actually loaded by the process |
| `independent_observer_and_recovery` | observer at a separate identity, fencing, recovery |
| `kms_keys_encryption` | key management (KMS/HSM), rotation, encryption at rest |
| `hardware_vfs_powerloss` | power-loss, torn-write, ENOSPC and VFS fault evidence |
| `privacy_regulatory_review` | data inventory, retention, DPIA under Swiss FADP |
| `independent_security_review` | external security review / penetration test |

Evidence listed by the gate file: `evidence/v0.7.22/test_evidence.json`, `focused_tests.log`,
`ABBA_request_binding.json`, `source_diff.patch` (originally under `EVIDENCE_V0722/`).

## Exit criteria G0–G6 (v0.7.21 overall audit)

| Gate | Exit criterion |
|---|---|
| G0 external monotonicity | separate hardware/admin domain, more than one independent mirror/monitor or an HSM monotonic counter, evidence against joint snapshots, no silent bootstrap/re-key paths |
| G1 mandatory writer | production distribution without importable research-only bypass APIs; direct store/key access blocked at OS level; per-UID/mTLS/authz |
| G2 reliable commit observation | attenuated witness chains, trusted clock/sequence/fencing, complete recovery and network-partition matrix; idempotent replay |
| G3 supply chain | patched, actually loaded SQLite library; builder attestation; no signing key in the repository |
| G4 data-protection evidence | data flow, data-subject rights, retention, deletion, incident and DPIA screening |
| G5 robustness | fsync/ENOSPC/torn-write/power-loss, two different host/administration zones, P95/P99 and 10k/100k history |
| G6 independent review | threat model, security audit, Swiss FADP review, documented acceptance |

"Release may switch to GO only when all mandatory P0 gates are met." Green tests, self-signed
metadata or a process-local simulator cannot change the NO-GO
(`promotion_policy` in `reports/release-gates/RELEASE_GATES.json`, v0.7.5).
