# Linux re-run of the v0.7.22 research bundle — 2026-10-27

**Result: 430 of 430 tests pass on Linux from a byte-identical reconstruction of the v0.7.22
bundle, as root with 0 skips. `anchor_wire` passed 10 of 10 repetitions in 10.4–11.1 s.**
The release decision stays **NO-GO**: these tests check local invariants, and every open P0 gate
of `RELEASE_GATES_V0722.json` is outside what they can show (see [docs/ROADMAP.md](../../docs/ROADMAP.md)).

This folder is not part of the import. It is checked by nobody but its author: it was produced in
the same Claude Code maintenance channel that assembled this repository, not by an independent
reviewer.

## Why

The v0.7.22 audit (`reports/audits/AUDIT_V0722.md`) could not finish the multi-process
`anchor_wire` group and therefore did not claim a 430-test pass. Roadmap item P0-1 asks for the
complete `anchor_wire` suite to be stabilised and for the 430-test regression from a fresh package.
CI so far ran 402 tests and left `anchor_wire` to a manual job that had never been started.

## Method

1. **Fresh package.** The flat bundle directory `Equal3_v0722_Research/` was rebuilt from the
   repository using the `original_path` column of `evidence/manifests/PATH_MAPPING.tsv`
   (382 files). In that directory, `sha256sum -c MANIFEST_V0722.sha256` returned rc 0, and the
   manifest's own SHA-256 is `fa6256361d7a9d45b52e1f4eae6880631e7851a6fae6422247575aea0f8ff5f8`,
   the value pinned in `tools/verify_provenance.py`. The tested tree is therefore byte-identical
   to the bundle's manifest. The zip itself was not downloaded again.
2. **Runner.** `tools/run_test_groups.py` (added with this folder) runs the 12 groups of the
   v0.7.22 audit, each in its own process group with a 300 s limit, and writes the JSON files here.
3. **Two privilege levels.** The separate-UID tests drop to UID 65534 and only run as root.
   The root run used `--require-no-skips --expect-total 430`. The non-root run (a separate
   unprivileged account) used `--expect-total 430`.
4. **Repetition.** `anchor_wire` alone, 10 times in a row as root, each with a 120 s hang limit.

Environment (from the JSON): Linux x86_64, glibc 2.39, Python 3.13.17, cryptography **46.0.4** (the pinned version),
SQLite **3.45.1** (the audit environment reported SQLite 3.46.1; neither
is a patched build, see P0-4), repository commit `4435627`. The runner script used was the version
in this commit; it was not yet committed when it ran, so the JSON names the parent commit.

## Results

| Run | File | Tests run | Skipped | Failed | Time |
|---|---|---:|---:|---:|---:|
| fresh bundle, root | [fresh_bundle_root.json](fresh_bundle_root.json) | 430 | 0 | 0 | ≈ 31 s |
| fresh bundle, non-root | [fresh_bundle_nonroot.json](fresh_bundle_nonroot.json) | 430 | 4 | 0 | ≈ 29 s |
| `anchor_wire` × 10, root | [anchor_wire_repetitions.json](anchor_wire_repetitions.json) | 10 × 28 | 0 | 0 | 10.4–11.1 s each |

Per-group counts match the counts reported by the v0.7.22 audit (and the v0.7.21 run for
`anchor_wire`) exactly.

### The four root-only tests

Without root these tests skip, so CI up to commit `4435627` never ran them (its log shows
`OK (skipped=3)` for the writer group and `OK (skipped=1)` for the anchor base group):

| Module | Test | What it checks |
|---|---|---|
| `test_writer_service_v0714` | `test_untrusted_public_key_and_parent` | a root-provisioned public key is accepted at 0644 and rejected once group/world-writable |
| `test_writer_service_v0714` | `test_runtime_gate_called_at_startup_and_failclosed` | with a separate writer UID, a failing signed runtime policy stops `serve()` before the socket exists |
| `test_writer_service_v0714` | `test_real_linux_uid_boundary_separate_client` | a client at another UID cannot write or read the DB/secret |
| `test_anchor_v079` | `test_separate_uid_can_connect_but_cannot_read_anchor` | the writer UID can use the socket but cannot read the anchor DB or reviewer key |

All four pass as root, both in the repository tree and in the reconstructed bundle.

## What this does not show

- **Why the audit environment hung.** `anchor_wire` did not hang here in 12 runs (10 repetitions,
  the root run and the non-root run). The cause in the audit environment is unknown. One possible
  cause is a helper process that keeps the
  output pipe open after its parent is gone, so the reader never sees EOF. The runner's own tests
  show that this class blocks a naive `communicate()`. It is not shown to be the audit cause.
- **Independence.** Same maintenance channel as the import, one machine, one kernel, one
  filesystem. No power-loss, ENOSPC or VFS faults (P0-6), no second host (P0-3).
- **A GitHub Actions root run.** The new CI job `research-tests-root` is expected to reproduce the
  root result. Its first run on the pull request that adds this folder is the evidence for that,
  not this README.

## Pitfall recorded for reproduction

As root, the UID-drop tests fail with `PermissionError` (not skip) if UID 65534 cannot read
the interpreter, the research modules or `TMPDIR`, e.g. a venv inside a private home or scratch
directory. That is an environment error, not a test result. Stage a world-readable copy as the CI
job does.

## Kurzfassung (Deutsch)

Aus einem byte-identisch rekonstruierten v0.7.22-Bundle (`sha256sum -c` rc 0) laufen unter Linux
als root **430 von 430 Tests ohne Skip**. `anchor_wire` lief 10 von 10 Mal durch, je etwa 11 s.
Ohne root werden 4 UID-Isolationstests übersprungen. Die bisherige CI hat genau diese 4 Tests nie
ausgeführt. Ab jetzt laufen `anchor_wire` und eine root-Lane in jeder CI. Warum `anchor_wire` in der
Audit-Umgebung hing, bleibt offen. Der Freigabeentscheid bleibt **NO-GO**.
