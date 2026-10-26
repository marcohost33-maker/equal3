# Equal3 v0.7.12 – Authenticated Genesis & Reads (Research)

**Safety:** RESEARCH ONLY / NO-GO for production and sensitive data.

This bundle fixes a demonstrable authenticated-initial-state verification bug plus an unverified raw-read path. It also rejects legacy unsealed history in witness/guarded reads. See `AUDIT_V0712.md`, `ROADMAP_V0712.md`, `RELEASE_GATES_V0712.json` and `EVIDENCE_V0712/`.

## Test

```sh
python -W error::ResourceWarning -m unittest discover -s . -p 'test_*.py' -q
sha256sum -c MANIFEST_V0712.sha256
```

Tests use synthetic data and may launch subprocesses and take over one minute. Never equate a passing unit suite with a production certification.

## Reproduce negative first and benchmark

```sh
python EVIDENCE_V0712/falsification_v0712.py /path/to/Equal3_v0711_Research . /tmp/falsification.json
python EVIDENCE_V0712/benchmark_reads_v0712.py /path/to/Equal3_v0711_Research . /tmp/benchmark.csv /tmp/summary.json
```

The benchmark asserts that original and candidate import their respective `state_store.py` source; it is a noisy local microbenchmark, **not a production latency guarantee**.

For official SQLite G0, `build_sqlite_v0711.py` is an offline recipe, **not proof a patched library is installed**.

Do not upload secrets, personal data, or databases to this research bundle. File-level SHA-256 manifest is not a digital signature.
