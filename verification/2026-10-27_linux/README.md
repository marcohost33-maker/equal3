# Linux re-run of the v0.7.22 research bundle — 2026-10-27

**Result: 430 of 430 tests pass on Linux from a byte-identical reconstruction of the v0.7.22
bundle, as root with 0 skips; every group runs exactly the count the audit reported.
`anchor_wire` passed every run here (10 dedicated repetitions in 10.4–11.1 s, plus the full runs
and a CPU-starved run). GitHub Actions reproduced 430/430 as root with 0 skips.**
The release decision stays **NO-GO**: these tests check local invariants, and every open P0 gate
of `RELEASE_GATES_V0722.json` is outside what they can show (see [docs/ROADMAP.md](../../docs/ROADMAP.md)).

This folder is not part of the import. It was produced in the same Claude Code maintenance channel
that assembled this repository, not by an independent reviewer.

## Why

The v0.7.22 audit (`reports/audits/AUDIT_V0722.md`) could not finish the multi-process
`anchor_wire` group (`evidence/v0.7.22/test_evidence.json`: "TIMEOUT") and therefore did not claim
a 430-test pass. Roadmap item P0-1 asks for the complete `anchor_wire` suite to be stabilised and
for the 430-test regression from a fresh package. CI up to commit `4435627` ran 402 tests, 4 of
them skipped, and left `anchor_wire` to a manual job that had never been started.

## Method

1. **Fresh package.** The flat bundle directory `Equal3_v0722_Research/` was rebuilt from the
   repository using the `original_path` column of `evidence/manifests/PATH_MAPPING.tsv`
   (382 files). In that directory `sha256sum -c MANIFEST_V0722.sha256` returned rc 0, and the
   manifest's own SHA-256 is `fa6256361d7a9d45b52e1f4eae6880631e7851a6fae6422247575aea0f8ff5f8`,
   the value pinned in `tools/verify_provenance.py`. The tested tree is therefore byte-identical
   to the bundle's manifest. The zip itself was not downloaded again.
2. **Dependencies.** A fresh venv installed with
   `pip install --require-hashes --only-binary :all: -r tools/requirements-ci.lock`
   (cryptography 46.0.4, cffi 2.1.1, pycparser 3.12; every hash from PyPI).
3. **Runner.** `tools/run_test_groups.py` runs the 12 groups of the v0.7.22 audit with
   `python -B -W error::ResourceWarning -m unittest -v`. Each group runs in its own process group
   with a 300 s limit. A preflight check runs first (TMPDIR length; as root, paths reachable by
   UID 65534). The output records the ids of skipped tests and any helper processes left behind.
4. **Two privilege levels.** Root: `--require-no-skips --expect-total 430 --expect-reported`.
   Non-root (a separate unprivileged account): `--expect-total 430 --expect-reported` plus exactly
   four `--allow-skip` ids (below).
5. **Repetition.** `anchor_wire` alone, 10 times in a row as root, each with a 120 s hang limit
   (plain `unittest -q`, before the runner existed).

Environment (from the JSON): Linux x86_64, glibc 2.39, Python 3.13.17, cryptography 46.0.4,
SQLite **3.45.1** (the audit environment reported SQLite 3.46.1; neither is a patched build, see
P0-4). The JSON names the commit the runner was started from; the runner file was the version committed
together with these files in `c13c08c` (`tools/run_test_groups.py` SHA-256
`2869edd30babc718b0392a1d0f9c28e66ba9aa1a4a3da1f1cfd27b7bf2fb82d5`). Later versions add SQLite
library checks and do not change how groups are run or counted.

## Results

| Run | File | Tests run | Skipped | Failed | Leftover processes |
|---|---|---:|---:|---:|---:|
| fresh bundle, root | [fresh_bundle_root.json](fresh_bundle_root.json) | 430 | 0 | 0 | 0 |
| fresh bundle, non-root | [fresh_bundle_nonroot.json](fresh_bundle_nonroot.json) | 430 | 4 (allowed ids) | 0 | 0 |
| `anchor_wire` × 10, root | [anchor_wire_repetitions.json](anchor_wire_repetitions.json) | 10 × 28 | 0 | 0 | – |
| GitHub Actions run 40465039728, root job, commit `195845e` | CI log | 430 | 0 | 0 | – |
| GitHub Actions run 40465039728, non-root job, commit `195845e` | CI log | 430 | 4 | 0 | – |

Per-group counts equal the counts reported by the v0.7.22 audit (and by the v0.7.21 run for
`anchor_wire`); `--expect-reported` enforces this per group, not only in total.

### The four root-only tests

Without root these tests skip. CI up to commit `4435627` never ran them (its log shows
`OK (skipped=3)` for the writer group and `OK (skipped=1)` for the anchor base group):

| Test id | What it checks |
|---|---|
| `test_writer_service_v0714.WriterBoundaryTests.test_untrusted_public_key_and_parent` | a root-provisioned public key is accepted at 0644 and rejected once group/world-writable |
| `test_writer_service_v0714.WriterBoundaryTests.test_runtime_gate_called_at_startup_and_failclosed` | with a separate writer UID, a failing signed runtime policy stops `serve()` before the socket exists |
| `test_writer_service_v0714.WriterBoundaryTests.test_real_linux_uid_boundary_separate_client` | a client at another UID cannot write or read the DB/secret |
| `test_anchor_v079.GroupSocketIsolationTests.test_separate_uid_can_connect_but_cannot_read_anchor` | the writer UID can use the socket but cannot read the anchor DB or reviewer key |

All four pass as root, both locally and in the CI root job.

## Why did `anchor_wire` hang in the audit? Hypotheses tested

Details and raw numbers: [hang_hypotheses.json](hang_hypotheses.json).

| Id | Hypothesis | Measurement | Verdict |
|---|---|---|---|
| H1 | long TMPDIR breaks AF_UNIX sockets | TMPDIR ≤ 73 characters passes, 74 fails with `OSError: AF_UNIX path too long`; a 115-character TMPDIR fails all 28 `anchor_wire` tests in 5.4 s | not a hang (it fails fast); kept as a hard limit, now a preflight check |
| H2 | daemons or helpers survive a test | no `anchor_wire.py` process after runs; 0 leftover processes in all 12 groups | refuted here |
| H3 | CPU starvation | one core shared with 3 busy loops: 28/28 OK in 28.0 s | refuted as a hang cause |
| H4 | a wall-clock limit of the audit sandbox | v0.7.21 there: anchor group 37.4 s, equal group 14.3 s (3.1–3.4 s here), so about 4–5× slower; the v0.7.22 evidence records only "TIMEOUT" | most consistent, **not proven** |

## Corrections to the first version of this folder (same day)

- **Runner defect, fixed.** The first `run_test_groups.py` read test output through a pipe. A
  helper process that leaves the process group and inherits stdout keeps that pipe open, so a
  *passing* group blocked until the helper exited and was then reported as a timeout (the
  bpo-26534 class). The negative-first test `test_detached_helper_does_not_block_a_passing_group`
  failed on that version and passes now. Output now goes to a temporary file. The leader is
  awaited with `waitid(WNOWAIT)` and the group is killed before the leader is reaped, so the
  process-group id cannot have been reused by then.
- **Gate too weak, fixed.** The non-root CI job allowed any number of skips. It now allows exactly
  the four ids above. Both jobs also check every group's count against the report.
- **Supply chain, fixed.** CI installed `cryptography==46.0.4` without hashes; it now installs from a
  hash lock, wheels only. A negative probe with all cryptography hashes altered fails with a hash
  mismatch. With only one hash altered, pip silently chose another hashed wheel (manylinux_2_28
  instead of 2_34) and never installed an unverified file.
- **Evidence retention.** The CI jobs now upload their JSON evidence (90 days).
- **Wording.** The first version said `anchor_wire` "did not hang in 12 runs"; the actual number of
  local runs was higher (see results), and the CI runs are now listed separately.

## What this does not show

- **The audit hang's cause** (H4 is an inference, not a measurement of that environment).
- **Independence.** Same maintenance channel as the import, one machine, one kernel, one filesystem.
  No power-loss, ENOSPC or VFS faults (P0-6), no second host (P0-3).

## Reproduction pitfalls

- **TMPDIR at most 73 characters.** Python's `tempfile` silently falls back to `/tmp` if TMPDIR
  does not exist, so a too-long TMPDIR only bites when the directory exists.
- **As root,** the UID-drop tests fail with `PermissionError` (they do not skip) if UID 65534 cannot
  reach the interpreter, including the directories of a venv symlink, the research modules or
  TMPDIR. The runner's preflight now reports exactly which directories block. To avoid it, stage a
  world-readable copy as the CI root job does.

## Kurzfassung (Deutsch)

Aus dem byte-identisch rekonstruierten v0.7.22-Bundle (`sha256sum -c` rc 0) laufen unter Linux als
root **430 von 430 Tests ohne Skip**, und jede Gruppe hat genau die gemeldete Anzahl. GitHub Actions
bestätigt das im root-Job. Ohne root dürfen nur noch genau die 4 UID-Isolationstests übersprungen
werden; die bisherige CI hat diese 4 Tests nie ausgeführt.

Zum Hänger im Audit: Pfadlänge (H1), übrig gebliebene Prozesse (H2) und CPU-Mangel (H3) erklären
ihn nicht. Am besten passt ein Zeitlimit der Audit-Sandbox (H4), bewiesen ist das nicht.

Bei der Selbstprüfung fand ich drei Lücken in der eigenen ersten Fassung und habe sie behoben:
- einen Pipe-Hänger im Runner,
- ein zu weiches Skip-Gate,
- ungehashte Abhängigkeiten.

Der Freigabeentscheid bleibt **NO-GO**.
