# === / Equal3 v0.7.13 – DELETE/EXTRA StateStore Research

**Status: RESEARCH / NO-GO. Not production approved.**

This release builds on original v0.7.12 and adds an explicitly selected rollback-journal
option to `StateStore` and the local CLI. The old default remains WAL/FULL for backwards
compatibility; no migration is performed. Python 3.13.5 / SQLite 3.46.1 were used in the
research test environment. This version has NOT upgraded SQLite or provided an external
attested signer, OS-mandated exclusive writer, independent anchor, at-rest encryption or a
hardware power-loss fault test.

## New mode

* `StateStore.create(path, key=key, initial=b'...', journal_mode='DELETE')`
* `StateStore(path, key=key, journal_mode='DELETE')`
* `store_cli.py init DB INPUT --key-file SECRET --journal-mode DELETE`
* Other CLI subcommands accept `--journal-mode DELETE` and must match the database.

`PRAGMA journal_mode=DELETE` and `PRAGMA synchronous=EXTRA` are checked for each new
connection. A read-only SQLite file-header preflight rejects WAL-mode DB files *before*
opening the regular connection. WAL sidecars, symlinked database paths and policy changes
are rejected in DELETE mode. `checkpoint()` is only meaningful for WAL and is rejected.
Backups retain and verify the selected mode; no plaintext backup is a secure backup.

The header check is a narrow best-effort local preflight, NOT a hostile VFS or same-UID
race defense. A privileged writer with OS-owned database/secrets remains required.
The old WAL default on the unpatched Python-linked SQLite still blocks production.

## Run tests

```shell
python -W error::ResourceWarning -m unittest discover -s . -p 'test_*.py' -q
python -W error::ResourceWarning -m unittest test_v0713_rollback -q
python benchmark_v0713_journal.py
```

## Reference docs

* `AUDIT_V0713.md` for negative-first test results, measurement limits and remaining risks
* `ROADMAP_V0713.md` for P0, P1 and migration release gates
* `RELEASE_GATES_V0713.json` machine-readable release hold
* `EVIDENCE_V0713/journal_benchmark.csv` original synthetic benchmark rows
* `MANIFEST_V0713.sha256` integrity of each file; unsigned, not a provenance attestation

**No Google Drive or GitHub source files were modified by the local build.**
