# Contributing

Equal3 is a research record with release decision **NO-GO**. Contributions are welcome if they keep
that record honest.

## Before you start

- Read the [README](README.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and the newest audit
  (`reports/audits/AUDIT_V0722.md`).
- Do not propose changes that claim production readiness. A green test run does not change the
  NO-GO status (see [docs/ROADMAP.md](docs/ROADMAP.md)).

## Development setup

Linux or another POSIX system, Python 3.13:

```sh
python3.13 -m venv .venv && . .venv/bin/activate
pip install -r research/REQUIREMENTS_RESEARCH_GATE.txt
python tools/verify_provenance.py
python -m unittest -v tools/test_verify_provenance.py
python tools/run_test_groups.py --expect-total 430
```

`tools/run_test_groups.py` defines all test groups (CI uses it). Four separate-UID tests only run
as root; see `verification/2026-10-27_linux/README.md` for staging a world-readable tree. Keep
`TMPDIR` at most 73 characters. If you change the research dependency, regenerate
`tools/requirements-ci.lock` with hashes for every file of each release.

## Rules for changes

1. **Imported files are never edited in place.** Everything under `research/`, `reports/` and
   `evidence/` that is listed in `evidence/manifests/PATH_MAPPING.tsv` is byte-identical to its
   source; `tools/verify_provenance.py` fails otherwise. A research change becomes a new version
   with its own manifest, evidence and audit, added next to the existing ones.
2. **Negative first.** A fix comes with a test that fails on the unchanged code, then passes on the
   changed code — the negative-first method the audit rounds use. Record both runs.
3. **Claims need evidence.** Every number in a report or PR names how it was produced (command,
   environment, commit). Self-reported numbers are labelled as such.
4. **Synthetic data and keys only.** Never add real secrets, personal data or production paths.

## Pull-request checklist

- [ ] `python tools/verify_provenance.py` passes
- [ ] `python -m unittest -v tools/test_verify_provenance.py` passes
- [ ] `python tools/run_test_groups.py --expect-total 430` passes on Linux; skips and root/non-root are stated
- [ ] new behaviour has a negative-first test
- [ ] no imported file changed; docs updated (CHANGELOG, AUDIT_HISTORY if a round is added)
- [ ] no secrets, personal data or absolute user paths

## Versioning

Research versions are named `0.7.N-research`. There are no release tags for NO-GO states.

## Coding style

Follow the style of the surrounding research code; new tooling uses the standard library where
possible, explicit error paths and fail-closed exits.

## Security issues

See [SECURITY.md](SECURITY.md).
