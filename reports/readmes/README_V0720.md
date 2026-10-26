# Equal3 0.7.20 — commit checkpoint witness (research-only)

This supplement builds on v0.7.19 and **does not migrate or modify any existing user database**. It contains an additional `CommitWitnessLedger` and `CommitGatedWriterCore` reference adapter.

## Trust model

The witness database is a locally sealed SQLite file, not nonrollbackable storage. Its public replies are nonce-bound Ed25519 signatures; this proves only the signer's claim. Its `publish` requires a separately signed *post-anchor-finalization* observation matching the authenticated StateStore receipt. The attester must be provisioned and run independently of the writer and anchor. `CommitGatedWriterCore` must become the sole public production entrypoint before release. A threat actor able to roll back all three stores can still win.

## Research workflow

1. Create a fresh v2 `StateStore` with `journal_mode='DELETE'` and bootstrap an anchor at version zero.
2. Bootstrap the witness against the **same genuine genesis position** in a private (0700) witness-owned directory. Provision a witness-only seal key, its separate Ed25519 signer and a pinned attester public key; bootstrap is offline only.
3. Let the protected writer prepare and commit (PENDING), then have a separately authorised reviewer finalize the matching anchor with independent observation.
4. Have a separately trusted observer call `issue_final_checkpoint` **after** finalisation. Submit the resulting short-lived Ed25519 evidence to `CommitWitnessClient.publish` for exactly one CAS advancement.
5. Create `CommitGatedWriterCore` and expose only its `dispatch`. Every successful status / idempotent reply requires witness = anchor = authenticated SQLite head. Outage or divergence => HOLD.

### Reference executable (not production-approved)

`python commit_witness_daemon_v0720.py --db-path /private/witness.db --socket-path /private/witness.sock --signer-key-file /private/signer.raw --seal-key-file /private/seal.raw --attester-public-key-file /etc/equal3/attester.ed25519 --deployment-id research1`

`--attester-public-key-file` must be root-managed using the existing file safety reader. The server does not self-bootstrap. The socket is 0600 in a private directory; same-UID clients only. Independent hosts, secure clocks, TLS, root governance and real hardware antirollback remain OUT OF SCOPE.

### Tests / benchmarks

`python -W error::ResourceWarning -m unittest -q test_external_commit_witness_v0720`

`python run_v0720_suites.py`

`python benchmark_v0720.py`

See `AUDIT_V0720.md` and `ROADMAP_V0720.md` for proofs and limitations. All preexisting `v0719` evidence remains historical, not evidence for the new module.
