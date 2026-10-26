# Equal3 v0.7.21 — Cross-Version Security Re-Audit (research)

Release decision: **NO-GO**. This archive extends v0.7.20 but does not constitute an audited deployable security service.

## New code

- `external_commit_witness_v0720.py`: signed post-final observation must remain within authenticated issued/expires window **after acquisition of SQLite's write lock**, before CAS or idempotent acceptance.
- `test_commit_floor_expiry_v0721.py`: two executable tests; one simulates a deterministic clock jump across verifier → CAS.
- `EVIDENCE_V0721/negative_first_clock_jump.json` records baseline v0.7.20 erroneously accepted a now-expired valid signature, while v0.7.21 rejects it. SHA-256-binds both tested source modules.
- `run_v0721_suites.py`: 12 separate test groups, 427 assertions; 425 inherited test cases and 2 additional tests. Source is pinned to the packaged files.

## Exact verification

Run from extracted root:

```sh
python -W error::ResourceWarning run_v0721_suites.py
sha256sum -c MANIFEST_V0721.sha256
```

The local filesystem and Trust-Root environment requirements apply; use only a disposable test environment. No tests here prove independent hardware-monotonic rollback protection or actual storage power-loss safety. Tests use research-only keys and APIs.

## Reports

- `AUDIT_GESAMT_V0721_2026-10-25.md`: full time-series, constructive critique, residual risks, scientific formulas, CodeFactory transfer.
- `ROADMAP_V0721.md`: P0 and P1 Exit criteria.
- `COMPLIANCE_TRANSFER_V0721.md`, `CODEFACTORY_TRANSFER_V0721.md`: cross-project transfer.
- `RELEASE_GATES_V0721.json`: explicit NO-GO contract.
- `EVIDENCE_V0721/ABBA_CAS_publish.csv`: real local 4-round ABBA benchmark and source hashes.

## Limitations

- Current host uses unpatched SQLite 3.46.1; although DELETE/EXTRA avoids the named WAL-reset path in the protected research components, runtime provenance remains P0.
- The witness is local and can be restored with its database; older research APIs are still importable.
- The wall clock is not a trusted external monotone source.
- Manifest is not independently signed, so it proves internal consistency only.
- No GitHub changes, no production deployment, no external KMS/HSM or independent security/compliance attestation.
