# Equal3 v0.7.19 — Critical engineering and security audit

**Date:** 2026-10-25. **Classification:** reproducible research; **PRODUCTION NO-GO**.

## 1. Original deficiency (v0.7.18)

`RootControlledCASAnchor(..., min_epoch=X)` enforces `local_epoch >= X`, but the caller controls `X` and the API cannot verify its origin or freshness. A coherent restoration of the local databases together with a reset `min_epoch=0` undoes the intended rollback defense. The original baseline test `test_external_epoch_floor_rejects_rollback` explicitly proves this property. Simply adding a local HMAC or an additional local SQLite file would not solve it.

## 2. Implemented research boundary (v0.7.19)

* `WitnessLedger`: separate SQLite `DELETE/EXTRA` monotone epoch CAS; rejects replay, invalid root certificate, invalid predecessor, inconsistent root fingerprint and corrupted records; refuses implicit bootstrap, nonprivate parent and insecure DB file permissions.
* `WitnessServer`: bounded line-delimited AF_UNIX JSON interface; opaque errors; private socket mode `0600`. **No cross-UID connectivity on this default socket.** Separate Unix process does not by itself establish independent trust.
* `WitnessClient`: per-call `os.urandom(32)` challenge; Ed25519 verify against pinned public key, exact schema/identity checks, bounded response size and timeout; network failures imply HOLD.
* `WitnessGatedCASAnchor`: checks live signed witness on every authenticated load. Exact match of epoch and attester fingerprint, not just a caller-stated lower bound. Authorization of actual SQLite writes still uses pre-existing root/attester/reviewer paths.
* `anchor_wire.py`: rooted normal mode requires pinned witness public key + socket; static floor accessible only via explicit `research_static_floor_only`/CLI `--allow-static-floor-research-only`. Startup verifies witness status before opening an RPC socket to writers.
* `witness_daemon_v0719.py`: provisioned read-only-open CLI for research service; witness key is outside the anchor process. This is not network-remote or HSM-backed.

## 3. Evidence / falsification

The new negative test suite covers live challenge; changed nonce signatures; down/offline witness; rogue signer; foreign deployment/root/store; signed response replay; unauthorized root signature; epoch replay/jump; genesis/hardlink/symlink/file-mode boundary; signer/root/attester-role collisions; duplicate/modified witness SQL rows; before/after ordering of local rotation vs witness CAS; removal of static floor default and startup fail closed.

**Important deliberate counterexample:** restoring both the local anchor AND witness to coherent old snapshots is accepted. The service signing key remains valid and signs the reset floor. True nonrollback requires a genuinely independent monotone retention boundary. Also a commit rollback without an attester epoch change will not be rejected by this epoch witness.

## 4. Measurement

`benchmark_v0719.py` measures local SQLite anchor status with and without live AF_UNIX challenge verification. Four ABBA passes and 160 measured status calls per pass, with 40 warmups. The data is synthetic same-host same-UID, not end-to-end production or independent-host latency. Measurements are stored in `EVIDENCE_V0719/benchmark_epoch_witness.csv` and bind source hashes. Measured median of four round medians: static 0.2438 ms, witnessed 1.0871 ms (4.46x; +0.8433 ms). These are measured local values, not requirements; noise and test-environment limitations apply.

## 5. Critical residual P0 gaps (not closed)

1. No genuinely independent anti-rollback witness: same user/storage/host rollback counterexample demonstrated.
2. Witness advances only trust epoch. Independent monotonic **commit** version/digest evidence absent.
3. Two local and remote transactions are not atomic: crash after first update leaves HOLD requiring separate signed recovery. No automatic unsafe repair.
4. Witness identity can sign a rolled-back database after total compromise of its host. Hardware monotonic storage, transparency log with external auditors, replicated quorum, availability/failure split and formal consistency proofs not implemented.
5. TLS/mTLS/gateway authentication, remote governance, signer rotation, KMS/HSM, two-person approval and time-source security absent.
6. SQLite 3.46.1 local; officially patched runtime and origin provenance not yet integrated.
7. Physical VFS/powercut/ENOSPC, data-at-rest encryption, privacy impact and third-party security assessments absent.
8. StateStore and audit ledger O(n) historical verification remains a growth/performance concern.

## 6. Security decision

**NO-GO**. A local separate process plus a signed current-state challenge is an improvement in falsifiability and fail-closed architecture, not sufficient independent monotonicity. The next development must bind commits to durable independently monitored checkpoints and operate the witness on independently administered infrastructure. No GitHub push, merge or deployment.

References: https://www.rfc-editor.org/rfc/rfc9162.html ; https://theupdateframework.github.io/specification/v1.0.36/ ; https://www.sqlite.org/atomiccommit.html .

## 7. Test harness corrections

A preliminary new runner falsely reported `all_pass=false` even though all groups were green (its own aggregation included a summary field). A subsequent attempt to correct the calculation mistakenly treated a boolean summary field as a dictionary. Both rejected harness outputs are retained under `EVIDENCE_V0719/REJECTED_HARNESS_ONLY/`. The corrected script computes status before adding summary fields and sums the named test groups only. No accepted release total relies on either rejected harness run.
