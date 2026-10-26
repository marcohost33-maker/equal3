# Audit history

One row per audit round, oldest first. Verdicts and findings are quoted (shortened, translated
where the original is German) from the report named in the last column; the reports are kept
unchanged in [`reports/audits/`](../reports/audits/). The 007acc2 file name is the name under which
the same bytes were delivered to the review channel (`02_ANTWORTEN/`).

All reports were produced in the same research channel as the code. Several call themselves
"independent"; none of them is an external third-party security review (v0.7.8 states this
explicitly: "a self-performed, not an independent external security audit").

| Date | Round | Verdict | Main finding (negative first) | Fix in that round | Report (repository) / 007acc2 name |
|---|---|---|---|---|---|
| 2026-10-17 | Overall audit v0.1–v0.7.2 | Research, no production claim | NR-01: joint rollback of DB and signed witness is not detected | v0.7.2 external witness prototype, 7 abort points | `EQUAL3_GESAMTAUDIT_2026-10-17.md` / same |
| 2026-10-17 | v0.7.3 follow-up | Research only, release gate NO-GO | G-01: witness only a post-hoc check; `StateStore.apply` bypassable | `GuardedStore.apply` checks witness before write; one-step advance; genesis-only init | `EQUAL3_V073_KRITISCHES_FOLGEAUDIT_2026-10-17.md` / same |
| 2026-10-24 | v0.7.4 | NO_GO | NR-074-01: `verify()` accepted a receipt whose `proposal_hash` was changed to `bad` | HMAC receipt chain, consistent snapshots | `AUDIT_2026-10-24.md` / `2026-10-24_EQUAL3_v074_CriticalAudit_113Tests_NO_GO.md` |
| 2026-10-24 | v0.7.5 | Release NO-GO | non-atomic DB/witness, no independent monotonic trust, raw-writer bypass, plaintext | two-phase protocol with HOLD verdicts; `MemoryCASAnchor` (same process, not P0 closure) | `AUDIT_V075_2026-10-24.md` / `2026-10-24_EQUAL3_v075_IndependentProtocol_Audit_NO_GO.md` |
| 2026-10-24 | v0.7.6 | Research / release NO-GO | v0.7.5 test anchor lived in the same process without a durable journal | separate AF_UNIX anchor process with durable SQLite state, same host | `AUDIT_V076_2026-10-24.md` / `2026-10-24_EQUAL3_v076_DurableAnchor_CriticalAudit_NO_GO.md` |
| 2026-10-24 | v0.7.7 | Research / NO-GO | v0.7.6 authority accepted an offline SQL `UPDATE` (version 9) without detection; SQLite 3.46.1 WAL-reset bug | HMAC seal of the authority state; runtime refuses unpatched WAL (research override in tests) | `AUDIT_V077.md` / `EQUAL3_v077_CROSSVERSION_CRITICAL_AUDIT_2026-10-24.md` |
| 2026-10-24 | v0.7.8 | NO-GO | `consumed` and `review_log` rows not sealed: deleting a nonce was accepted | `audit_root` over all audit rows bound into the seal | `AUDIT_V078.md` / `EQUAL3_v078_CRITICAL_AUDIT_190_TESTS_NO_GO_2026-10-24.md` |
| 2026-10-25 | v0.7.9 | NO-GO | anchor used WAL on SQLite 3.46.1 (WAL-reset race) | anchor switched to `DELETE` journal + `synchronous=EXTRA`; UID socket test | `AUDIT_V079.md` / `EQUAL3_v079_CriticalAudit_206Tests_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.10 | NO-GO | NR-710-01: `receipt()` and duplicate `apply()` returned a forged digest without chain check | both paths authenticate the full receipt history (O(n)) | `AUDIT_V0710.md` / `EQUAL3_v0710_CriticalCrossReview_219Tests_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.11 | NO-GO | NR-0711-01: caller-supplied approval dict could be mistaken for an independent SQLite approval | Ed25519-signed runtime policy bound to deployment, ABI, library hash, source id | `AUDIT_V0711.md` / `EQUAL3_v0711_CriticalAudit_240Tests_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.12 | Production NO-GO | `read()` returned forged content; zero-receipt genesis state not authenticated | `read()` authenticates; genesis binding | `AUDIT_V0712.md` / `EQUAL3_v0712_CriticalAudit_250Tests_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.13 | Research / NO-GO | state store still exposed to the WAL-reset path; no patched SQLite obtainable | optional state-store mode `DELETE`/`EXTRA` | `AUDIT_V0713.md` / `EQUAL3_v0713_CriticalAudit_265Tests_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.14 | NO-GO | `StateStore.apply()` and the CLI have direct DB and key access | authenticated Unix-socket writer service under a separate UID | `AUDIT_V0714.md` / `EQUAL3_v0714_CriticalAudit_286SplitTests_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.15 | Research, NO-GO | writer service applied commits without contacting the anchor | `AnchoredWriterCore`: prepare at anchor → commit → HOLD until external review | `AUDIT_V0715.md` / `EQUAL3_v0715_AnchoredWriter_CriticalAudit_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.16 | Research / NO_GO | anchor finalised a prepared intent with a valid reviewer token although no SQLite commit happened | signed post-commit observation required at the authority | `AUDIT_V0716.md` / `EQUAL3_v0716_CriticalReview_AttestedCommit_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.17 | Research / NO_GO | NR-0717-01: re-open with a foreign attester key and deployment id was accepted | sealed `trust_binding` of store, deployment and key fingerprint | `AUDIT_V0717.md` / `EQUAL3_v0717_CriticalCrossReview_AttesterBinding_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.18 | Research / NO-GO | with the local `seal_key` the trust binding can be replaced | root-signed attester rotation, epoch +1, 300 s window | `AUDIT_V0718.md` / `EQUAL3_v0718_CriticalAudit_RootRotation_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.19 | Production NO-GO | `min_epoch` is caller-controlled; coherent restore with `min_epoch=0` undoes the defence | `WitnessLedger` + live signed epoch witness (nonce challenge) | `AUDIT_V0719.md` / `EQUAL3_v0719_CriticalAudit_LiveEpochWitness_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.20 | Release NO-GO | the epoch witness recorded only key increments, not every commit | signed commit-witness floor (version, digest, request id, fingerprints) | `AUDIT_V0720.md` / `EQUAL3_v0720_CriticalAudit_425Tests_NO_GO_2026-10-25.md` |
| 2026-10-25 | v0.7.21 overall audit | Release NO-GO | observation expiry was checked before the CAS write lock (61 s clock jump accepted) | expiry re-checked after `BEGIN IMMEDIATE` | `AUDIT_GESAMT_V0721_2026-10-25.md` / `EQUAL3_v0721_GESAMTAUDIT_2026-10-25.md` |
| 2026-10-25 | v0.7.22 re-audit | Research NO-GO | `_check_floor` compared version and digest but not `request_id`: a fork with the same version and value passed as `MATCH` | witness floor checked against the authenticated receipt of exactly that `request_id`; genesis requires a null id | `AUDIT_V0722.md` / `EQUAL3_v0722_CRITICAL_REAUDIT_NO_GO_2026-10-25.md` |

## Test-count statements per round (as reported)

The counts in the lineage table of the [README](../README.md) are the reports' own numbers. The
v0.7.21 overall audit marks the v0.7.14–v0.7.21 numbers as sums of separately run test groups.
The v0.7.22 re-audit reports 29/29 focused tests and the completed older groups (Equal 57,
Store 96, Runtime 21, Coordinator 23, Attester 24, Policy 14, Rotation 28, Epoch witness 26,
Writer 21, Anchor base 63) and states that the `anchor_wire` multi-process block did not finish,
so no overall 430/430 PASS is claimed.

## Benchmarks (as reported)

Most rounds from v0.7.3 on report local micro-benchmarks, many of them in ABBA order, with raw
data in `evidence/`. They come from one machine each, without confidence intervals; the reports
themselves warn against extrapolation. Example from v0.7.22: median of four ABBA run medians,
45 guarded queries each, v0.7.21 2.162565 ms vs v0.7.22 2.1602665 ms — "no robust performance
gain or loss".
