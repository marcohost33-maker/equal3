# === / Equal3 v0.7.5 — research-only two-phase anchor reference

**Date:** 2026-10-24  · **Release verdict:** **NO-GO** (not production-ready)

This additive development continues the reproducibly tested v0.7.4 bundle. It implements a *model* of explicit intent/preparation before SQLite commit, a monotonic compare-and-swap anchor, fail-closed recovery classification, and independent-review-token checking. **The anchor shipped in this bundle is a volatile Python in-process test double. It cannot provide actual independent anti-rollback, durable external attestation, or OS-enforced sole-writer isolation.** Never place sensitive or critical production data in this build.

## What's new

- `anchor_protocol.py`: `MemoryCASAnchor`, `CoordinatedStore`, formalized `Intent`, `Position`, diagnosis/status and review-token handling.
- `state_store.py`: `inspect_request(request_id)` returns the verified receipt, verified metadata and data from a **single** SQLite read transaction; existing public methods remain unchanged.
- `test_anchor_protocol.py`: independent correctness and falsification tests of this research contract, including torn protocol flow (not actual torn disk sectors), joint rollback with an intact authority and a counterexample for *recreated* volatile authority.
- `benchmark_v075.py`: consistent synthetic operation benchmarks and history-scaling measurements. Measurements exclude proposal generation; the prototype *includes* the per-write manual review operation. No real network/HSM latency is represented.

## Execution

```bash
python3 -m unittest discover -p 'test_*.py' -q
python3 benchmark_v075.py
sha256sum -c MANIFEST_SHA256.txt
```

> Existing `run_guarded_cli.py`/`GuardedStore` remains the separate optional v0.7.4 local-witness research path. `CoordinatedStore` is an **alternative experimental protocol** and is not integrated as a production deployment service.

## Safety model

- Trust the store's Python runtime, secret master key, the test anchor, reviewer key, and one cooperating writer. This is only a local reference test.
- The real environment must put the **writer, master key and authority** under distinct OS/service identities with authenticated endpoints, a durable monotonic authority on an independent fault domain, verified source-to-state provenance, effective ACLs, and deployment attestation.
- The DB commit and external anchor transition remain *non-atomic*. `NOT_COMMITTED_HOLD` and `COMMITTED_PENDING_HOLD` are both deliberately blocked until adjudication. `NO-GO` remains active.
- An attacker who can reset BOTH the DB and the volatile MemoryCASAnchor can recreate a matching old state. The included test explicitly exhibits this weakness.
- SQLite WAL and backups remain unencrypted and the raw writer remains accessible. No real power-cut/VFS-fault injection, pentest, DSFA or real-device acceptance tests are supplied.
- The internal reviewer signer is named `test_only_review_token` **on purpose**. Production software must not provide such a method to a coordinator/client; the secret belongs to a separate trust service.

## Explicit simulated workflow

1. `position_for_genesis(store)` requires authenticated V2 history at version 0 (still only a *local* bootstrap; independent attestation remains mandatory).
2. `CoordinatedStore.apply(signed_proposal)`: match anchored head -> validate and decode -> authority `prepare` CAS -> SQLite commit -> verify receipt and head from one snapshot -> return a **pending** transaction without automatic promotion.
3. `diagnose()` identifies `MATCH`, `NOT_COMMITTED_HOLD`, `COMMITTED_PENDING_HOLD`, `ROLLBACK_HOLD`, `DIVERGENCE_HOLD`, `CONFLICT_HOLD`, `INVALID_DB_HOLD`, etc.
4. An independently approved review token is checked by the **anchor** simulator. Only verified `COMMITTED_PENDING_HOLD` can finalize, and only verified `NOT_COMMITTED_HOLD` can abort. All other cases HOLD.
5. In the simulator every successful commit requires review deliberately; that is unsuitable for productive throughput. An actual service will require source-attested, backend-verifiable automated acknowledgements for normal commits and human escalation for uncertain commits.

Detailed PR/NR, threat model, release gates and measurements: `AUDIT_V075_2026-10-24.md`, `RELEASE_GATES.json`, `ROADMAP_V075.md`, `EVIDENCE/`.
