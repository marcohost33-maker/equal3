# === / Equal3 — critical four-reaction follow-up audit

**Date:** 2026-10-25. **Candidate:** v0.7.10 Research. **Result:** NO-GO.

## 1. Evidence basis

Reviewed v0.7.6–v0.7.9 artifacts, plus the actual v0.7.9 source. Original ZIPs passed CRC checks. Tests from the current modified source: **219/219 passed**, with ResourceWarning treated as error; see `EVIDENCE_V0710/regression_219.log`. Original test history 167/176/190/206 is historical, not independently rerun in this cycle.

## 2. Reproduced defect (NR-710-01)

V0.7.9 `StateStore.verify()` correctly catches a changed historical receipt HMAC chain, but both `StateStore.receipt(request_id)` and the duplicate replay branch of `StateStore.apply(same_proposal)` return the forged database digest without verifying the chain. Concrete input: valid one-commit store, offline `UPDATE receipts SET digest=X'4646...'` for the existing request ID. Outcome: verify=IntegrityError, raw receipt/replay return forged digest.

## 3. Repair (PR-710-01)

`StateStore.receipt` and duplicate-apply branches call `inspect_request()` to authenticate the complete receipt history in a pinned SQLite snapshot. Any broken tag/hash, deleted tag or malformed receipt triggers fail-closed IntegrityError. V1 legacy unsealed history is explicitly HOLD (not purported authenticated success). The 13 new security and runtime evidence tests pass, with full old suite 219/219. This intentionally introduces an O(N) replay-read regression.

## 4. Runtime provenance error (NR-710-02; PR-710-02)

Past preflight hashed `_sqlite3` extension, not the actual linked SQLite library; `ldd` and `/proc/self/maps` demonstrate effective `libsqlite3.so.0.8.6` loaded separately. New `runtime_evidence_v0710.py` inventories the dynamically mapped library path, device/inode, SHA256, SQLite source-ID and version. `release_preflight_v078.py` now includes this evidence. It does **not** assert a patched library: local runtime is SQLite **3.46.1**; upstream 3.54.1 exists but was not built or installed locally. A runtime pin must be approved out-of-band, as hash equality alone is not a digital signature.

## 5. Review of preceding four engineering responses

- v0.7.6: local persistent CAS and UID peer authorization were positive functional progress, not non-rollbackability; jointly rolling back StateStore and local authority remains possible.
- v0.7.7: authority HMAC seal protects one state row, but did not cover consumed nonces/review history until 0.7.8.
- v0.7.8: HMAC audit root and negative tests improved logs, with O(N) ledger scanning; no external append-only evidence.
- v0.7.9: DELETE/EXTRA removes the specific WAL-reset exposure from the authority DB and two-UID tests demonstrate a narrow Linux OS boundary; **StateStore still WAL on unpatched 3.46.1**. Raw authenticated-replay gap and incorrect implication about extension hashing were newly exposed here. Startup preflight is *not* an independent runtime deployment attestation.

## 6. Microbenchmarks (local, synthetic)

Source SHA hashes are in the raw CSV. Both variants use new temp stores, 1/50/250 receipts, 3 warmups, 20 measurements per method, median in milliseconds, sequential baseline and new tests without hardware isolation. Quittung latency v0.7.9→v0.7.10: N=1 0.362→0.651 ms; N=50 0.345→1.049 ms; N=250 0.334→2.866 ms. Idempotent apply N=250 0.958→3.710 ms. No confidence intervals, disk cache control, or production SLA.

## 7. Open findings and falsification boundaries

- External independent monotonic authority, separation from root/host rollback and commit attestation not solved.
- Live encryption of StateStore SQLite/WAL/SHM, backup/secret lifecycle, power-cut VFS lab, truly deployed service accounts and independent external review remain P0.
- Linked runtime SHA and inode are **inventory facts** subject to privileged path/in-place-rewrite threats. No vendor or independent signing.
- Full-history verification is intentionally linear; older legitimate receipts now more expensive. Authenticated checkpoints and narrow proofs need a design plus rollback/fork counterexamples before optimization.
- SQLite `journal_mode=DELETE` + `synchronous=EXTRA` has a documented durability benefit, not a universal protection against filesystem/hardware faults.
- Hash-manifest is unsigned. The prior wording 'signiertes Dateimanifest' was inaccurate; corrected to **SHA-256 integrity manifest**.

## 8. Web-verified references

- SQLite WAL reset race and affected versions: https://www.sqlite.org/wal.html
- SQLite 3.54.1 release and official source hash: https://www.sqlite.org/releaselog/3_54_1.html ; https://www.sqlite.org/download.html
- SQLite rollback journal synchronous EXTRA: https://www.sqlite.org/pragma.html#pragma_synchronous
- SQLite untrusted database security: https://www.sqlite.org/security.html
- SQLite crash VFS tests: https://www.sqlite.org/testing.html
- Python sqlite3 context-manager close lifecycle: https://docs.python.org/3.13/library/sqlite3.html

**Verdict:** Tested research hardening, **NOT production ready**. No runtime upgrade, external notarization, power-loss test, production deploy, GitHub push, or compliance table update performed.
