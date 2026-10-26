# Equal3 v0.7.19 — External epoch witness (research only)

**Decision: NO-GO for production.** Reference baseline v0.7.18. No prior code was deployed or pushed.

## Architecture

The version introduces `external_epoch_witness_v0719.py`, a separate AF_UNIX test witness holding a monotone trust **epoch** in its own SQLite database. `WitnessLedger.advance` requires an unexpired Ed25519 root-signed attester rotation certificate, compares exactly against the recorded prior epoch/attester fingerprint, and commits `n -> n+1` atomically. `WitnessClient.floor` sends a fresh 256-bit random challenge on every check, verifies the independently pinned witness Ed25519 signature, and checks deployment, store and root fingerprint. `WitnessGatedCASAnchor` requires a live witnessed **exact equality** of epoch AND attester fingerprint in addition to the existing local seal before allowing status/prepare/adjudicate. The anchored daemon (`anchor_wire.py`) now defaults to live witness mode in rooted configuration; allowing a caller-supplied static floor requires `--allow-static-floor-research-only`.

## Explicit non-guarantees

* Current laboratory witness runs under the same OS user/host as the test, in its own directory, with a local AF_UNIX socket. **This is NOT an independent storage, administrative or rollback domain.**
* This registry binds rotation epoch, NOT every committed SQLite state version/digest. It cannot catch a same-epoch rollback of the local databases. An external commit log/checkpoint remains P0.
* A joint rollback of the witness itself plus local databases defeats freshness: the signer signs the now-old current floor. Real hardware monotonic counters / independently administered append-only service, quorum/gossip, and rollback-resistant backups must be evaluated.
* No cryptographically atomic transaction spans local anchor and witness. Transition/recovery needs a human or separately authorized controller. In this prototype, local rotation may be recorded before witness advance; all further operations HOLD until signed witness CAS catches up. If witness advances first, local operations HOLD until local root-authorized rotation completes.
* A root-signed certificate on the witness API is necessary, but not sufficient as an externally witnessed proof of the local SQLite commit. This is an **epoch** mechanism only.
* Legacy `PersistentCASAnchor` and research-only paths remain in source; release policies must disable them, independently enforce OS separation, keys, crypto-at-rest, SQLite provenance and reviewer governance.

## Offline setup, lab-only

Use test fixtures in `test_external_epoch_witness_v0719.py` for reproducible provisioning and `WitnessLedger.bootstrap`. In a real deployment, root public key and witness public key must be immutable, independently provisioned, and the witness signing private key must never reside on the Writer or Anchor host. The `witness_daemon_v0719.py` CLI only opens already provisioned databases and expects credential files owned by the daemon UID, mode `0600`, with a socket directory owned by that UID at `0700`. There is no automated unverified migration/bootstrap.

Witness daemon (after external provisioning):

```sh
python witness_daemon_v0719.py \
  --db /private/witness/counter.db \
  --socket /private/witness/epoch.sock \
  --witness-private-key-file /private/keys/witness.key \
  --root-public-key-file /private/keys/root.pub
```

Anchor service now supports `--witness-socket` and `--witness-public-key-file` alongside the existing attester and root arguments. It rejects a missing or falsely signed witness before opening its Writer-facing socket. For research-only legacy tests, `--allow-static-floor-research-only --trusted-min-epoch 0` is an explicitly unsafe downgrade, not a supported production configuration.

## Recovery runbook

1. Stop writes, set HOLD, preserve append-only forensic records and snapshots.
2. Independently inspect old/new attester identities and the signed root rotation certificate.
3. Query fresh nonce-signed witness floor from pinned identity, not a local cached value.
4. Local epoch `n+1` and witness `n`: authorized operator submits the **same valid certificate** to witness CAS; check fresh witness response; resume only after exact match. This cannot be done if the authorization is expired: explicit reauthorization/recovery is required.
5. Witness `n+1` and local epoch `n`: validate signed certificate independently, apply authorized local root rotation (using audited breakglass/maintenance path, not ordinary gated read), verify equality and rollback status.
6. Any mismatch in store/deployment/root ID, evidence of witness compromise, expired cert or impossible state: stay in HOLD; do not auto-bootstrap or decrement floor.
7. For operation on separate hosts, implement mutual authentication, service rate limits, independent monitoring, crash recovery and durable monotonicity. None is demonstrated by local AF_UNIX tests.

## Reproduce

```sh
python -W error::ResourceWarning -m unittest -q test_external_epoch_witness_v0719
python run_v0719_suites.py
python benchmark_v0719.py
```

## External references

- RFC 9162 append-only transparency log and consistency proofs: https://www.rfc-editor.org/rfc/rfc9162.html
- Sigstore log inclusion, signed checkpoints and threat model: https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md
- TUF root threshold/rollback requirements: https://theupdateframework.github.io/specification/v1.0.36/
- SQLite rollback journal atomic commit: https://www.sqlite.org/atomiccommit.html
- SQLite synchronous=EXTRA semantics: https://www.sqlite.org/pragma.html#pragma_synchronous
