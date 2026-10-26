# Path mapping: original artefacts → repository

All imported files are **byte-identical** to their sources. Only paths changed. The complete
row-by-row table (405 rows: source, original path, repository path, SHA-256) is
[`evidence/manifests/PATH_MAPPING.tsv`](../evidence/manifests/PATH_MAPPING.tsv), and
`python tools/verify_provenance.py` checks every row, the shipped manifest and the absence of
unmapped files in `research/`, `reports/` and `evidence/`.

## Sources

| Source | Files | Identification |
|---|---:|---|
| `EQUAL3_v0722_REQUEST_LINEAGE_REAUDIT_2026-10-25.zip` (folder `Equal3_v0722_Research/`) | 382 | zip SHA-256 `4ade76c73c95c409f5c411a9042fce3dad7882bae2c308acca402c38e6eb3982`; 381 files listed in `MANIFEST_V0722.sha256` + the manifest itself |
| 007acc2 `02_ANTWORTEN/` | 2 | the two 2026-10-17 audits (v0.1–v0.7.3), not contained in the bundle |
| 007acc2 `06_WISSEN/` | 21 | 2026-10-17 transfer notes, fresh-zip rerun logs, v0.7.4 release gates — content not contained in the bundle (checked by SHA-256 against every bundle file) |

Files from 007acc2 whose content *is* already in the bundle (for example the per-version audits in
`02_ANTWORTEN/`, 19 of them byte-identical to `AUDIT_*.md`) were not imported a second time.

## Rules (bundle)

| Original location in bundle | Repository location | Files |
|---|---|---:|
| `*.py`, `REQUIREMENTS_RESEARCH_GATE.txt` (root) | `research/` (flat, unchanged names) | 79 |
| `AUDIT_*.md` | `reports/audits/` | 19 |
| `README.md` (root, still describing v0.7.8) | `reports/readmes/BUNDLE_ROOT_README.md` (renamed so it is not shown as folder README) | 1 |
| `README_V*.md` | `reports/readmes/` | 19 |
| `ROADMAP_V*.md` | `reports/roadmaps/` | 18 |
| `RELEASE_GATES.json`, `RELEASE_GATES_V*.json` | `reports/release-gates/` | 18 |
| `COMPLIANCE_*.md`, `CODEFACTORY_*.md` | `reports/transfer/` | 29 |
| `DEPLOYMENT_ISOLATION_V079.md`, `ENVIRONMENT_V076.json`, `ENVIRONMENT_V077.json`, `TEST_SUMMARY_V076.txt` | `reports/misc/` | 4 |
| `EVIDENCE/` (v0.7.4 and v0.7.5 evidence: 96 → 113 → 139 tests) | `evidence/v0.7.4-v0.7.5/` | 12 |
| `EVIDENCE_V076/` … `EVIDENCE_V0722/` | `evidence/v0.7.6/` … `evidence/v0.7.22/` | 175 |
| `EVIDENCE_V0721_runner.log`, `EVIDENCE_V0721_runner.rc` | `evidence/v0.7.21-runner/` | 2 |
| `MANIFEST_V0722.sha256` | `evidence/manifests/` | 1 |
| `HISTORICAL_MANIFESTS/*` | `evidence/manifests/historical/` | 5 |

## Rules (007acc2 supplementary)

| Original | Repository location | Files |
|---|---|---:|
| `02_ANTWORTEN/EQUAL3_GESAMTAUDIT_2026-10-17.md`, `02_ANTWORTEN/EQUAL3_V073_KRITISCHES_FOLGEAUDIT_2026-10-17.md` | `reports/audits/` | 2 |
| `06_WISSEN/EQUAL3_*_2026-10-17.md` (transfer, compliance, learning notes) | `reports/transfer/` | 6 |
| `06_WISSEN/EQUAL3_v074_RELEASE_GATES_2026-10-24.json` | `reports/release-gates/` | 1 |
| `06_WISSEN/EQUAL3_v07xx_FRESH_ZIP_*.{log,json}` | `evidence/fresh-zip-reruns/` | 14 |

## Why `research/` is flat

The tests import the modules by bare name (`from anchor_wire import ...`), start scripts by
relative path (`subprocess.Popen([sys.executable, '-u', 'anchor_wire.py', ...])`) and the
benchmarks resolve sibling files (`bench_seal_v077.py` reads `REFERENCE_V076_anchor_wire.py`).
Splitting code and tests into separate folders would have required changing files. Tests therefore
run with `research/` as working directory. Benchmarks and the historical `run_v07xx_suites.py`
runners write `EVIDENCE_*` folders next to themselves; those outputs are ignored by `.gitignore`.

## Known stale texts inside imported files

Imported files are kept as written. Some of them describe an older state, for example
`reports/readmes/BUNDLE_ROOT_README.md` ("Equal3 v0.7.8 Research Only") and
`reports/readmes/README_V0722.md`, whose first sections still describe v0.7.21 before the
"v0.7.22 correction" section. Paths inside imported texts (`EVIDENCE_V0721/...`,
`/mnt/data/...` working directories of the research environment) refer to the original layout.
