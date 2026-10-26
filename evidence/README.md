# Evidence (historical, self-reported)

These folders hold the evidence that each research round shipped: test logs, suite summaries,
benchmark CSV/JSON, negative-first falsification records, source diffs and SHA-256 manifests.

**Read them as self-reported research evidence.** They were produced in the same research
environment as the code. The SHA-256 manifests (`manifests/`) are **not independently signed**;
they show internal consistency of a delivery, not who produced it or that the runs happened as
described (finding NR-08). Benchmarks come from single machines without confidence intervals.

| Folder | Content |
|---|---|
| `v0.7.4-v0.7.5/` | original folder `EVIDENCE/`: v0.7.3 baseline (96 tests), v0.7.4 (113), v0.7.5 (139), coverage, benchmarks |
| `v0.7.6/` … `v0.7.22/` | original folders `EVIDENCE_V076/` … `EVIDENCE_V0722/` |
| `v0.7.21-runner/` | runner log and return code of the v0.7.21 suite run (bundle root files) |
| `fresh-zip-reruns/` | rerun logs of delivered zips, from the 007acc2 knowledge folder (`06_WISSEN/`) |
| `manifests/` | `MANIFEST_V0722.sha256` (covers the whole v0.7.22 bundle), `historical/` manifests of v0.7.12, v0.7.16, v0.7.18, v0.7.19, v0.7.21 (reference only), `PATH_MAPPING.tsv` |

Paths inside the files refer to the original flat bundle layout (`EVIDENCE_V0721/...`) or to the
research environment (`/mnt/data/...`). `v0.7.19/REJECTED_HARNESS_ONLY/` holds two runner
outputs that the v0.7.19 audit itself rejected as faulty aggregation ("No accepted release total
relies on either rejected harness run", `reports/audits/AUDIT_V0719.md`).

`PATH_MAPPING.tsv` and this README are the only files here that were added by the repository
assembly; `tools/verify_provenance.py` checks all others.
