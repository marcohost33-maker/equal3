# Full regression on SQLite 3.54.1 built from official source — 2026-10-27 (roadmap P0-4)

**Result: all 430 tests pass as root, with 0 skips, on SQLite 3.54.1. It was built from the official
sqlite.org amalgamation, and the test processes demonstrably mapped that library. On it, the
research WAL-reset gate opens without the research override for the first time. On the runner's
unpatched system SQLite the gate holds (negative control).** The release decision stays **NO-GO**.

Evidence: GitHub Actions run
[40483352618](https://github.com/marcohost33-maker/equal3/actions/runs/40483352618), commit
`2ff57dd`, job "research test groups on SQLite 3.54.1 built from official source (root)". Its
artifact `sqlite-3.54.1` (90 days) contains three files:
- `sqlite-build-evidence.json`
- `sqlite-runtime-3.54.1.json`
- `test-groups-sqlite-3.54.1.json`

## Why

- The v0.7.11 audit found that a signed runtime gate and an offline builder existed, but no patched
  build was actually deployed.
- P0-4 asks for an officially patched SQLite in the actual Python process, with build evidence and a
  complete new regression.
- The SQLite WAL-reset bug affects 3.7.0–3.51.2 and is fixed from 3.51.3 on. 3.52.0 was withdrawn,
  and backports are reported for 3.50.7 and 3.44.6. The research encodes exactly this policy in
  `anchor_wire.sqlite_wal_reset_safe()`.
- Every audit environment so far ran an unpatched SQLite (3.46.1, here 3.45.1). The "gate opens"
  branch had therefore never run: `test_anchor_v077` checks the hold only when the runtime is
  unpatched and asserts nothing on a patched one.

## Method (CI job, all steps in [.github/workflows/ci.yml](../../.github/workflows/ci.yml))

1. **Download.** `https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip`, with
   `curl --fail --proto =https --tlsv1.2`.
2. **Verify and build with the unmodified research builder** `research/build_sqlite_v0711.py`:
   - SHA3-256 of the ZIP `92281c86…8e30` and of `sqlite3.c` `e2b869d3…ee81`. Both pins are in the
     builder and are also listed by sqlite.org on its download page and in the 3.54.1 release log
     (second channel, checked by web search on 2026-10-27);
   - `SQLITE_SOURCE_ID` confirmed in the header;
   - build in an empty directory;
   - smoke test in a new interpreter, which must map exactly the built file.
3. **Stage.** The library is copied world-readable to `/srv/sqlite-3.54.1/`. It was measured that the
   dynamic loader silently skips a library that UID 65534 cannot read; the separate-UID tests would
   then fall back to the system SQLite.
4. **Runtime check** with [`tools/check_sqlite_runtime.py`](../../tools/check_sqlite_runtime.py),
   which calls the unmodified `release_preflight_v078.assess()` and `anchor_wire.require_sqlite_wal_safe()`.
   All of these must hold:
   - the version is 3.54.1 and the source id equals the release's;
   - the mapped path is `/srv/sqlite-3.54.1/libsqlite3.so.0`;
   - the SHA-256 of the mapped file equals the build's;
   - the gate opens without override.
5. **Regression.** All 12 groups as root with `LD_LIBRARY_PATH=/srv/sqlite-3.54.1:…`, run with
   `--require-no-skips --expect-total 430 --expect-reported --expect-sqlite 3.54.1`. As root, the
   runner's preflight also requires the loaded libsqlite3 to be readable by other users.
6. **Negative control** (non-root job, system SQLite): `check_sqlite_runtime.py --expect-gate hold`.

## Results (from the CI log of run 40483352618)

| Item | Value |
|---|---|
| archive SHA3-256 | `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30` (pin matched) |
| `sqlite3.c` SHA3-256 | `e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81` (pin matched) |
| source id | `2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76` |
| built `libsqlite3.so.0` SHA-256 | `02d0123b2e18c69dc806b4a38bdc8050b6239ba86e90ae7aa48ebd7b7c774025` |
| builder smoke test | new interpreter mapped the built file, `mapped_file_identity_consistent: true` |
| compiler / flags | gcc on ubuntu-24.04, `-O2 -fPIC -shared -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_FTS5=1 -DSQLITE_ENABLE_RTREE=1 -DSQLITE_ENABLE_MATH_FUNCTIONS=1` |
| runtime check | "SQLite 3.54.1 from /srv/sqlite-3.54.1/libsqlite3.so.0; WAL gate without override: open" |
| regression | 12 groups, **430 run, 0 skipped**, 0 leftover processes, euid 0, Python 3.13.16 |
| negative control | system SQLite of ubuntu-24.04: gate holds, version policy FAIL |

## Addendum after the cross-family review (2026-10-27)

GPT-6 (007acc2, session 45283d7d) asked for proof that a child dropped to UID 65534 maps the
patched library, not only the parent. `tools/check_sqlite_runtime.py --check-child-uid 65534` now
starts such a child the way the separate-UID tests do. The check requires the child to map the same
file with the same version and source id. Locally it detects the silent fallback: with the library
in a 0700 directory, the parent mapped the private copy and the child mapped the system SQLite.
Both root CI jobs run it. The same review noted that `GITHUB_SHA` of a pull_request run is the
merge commit, not the PR head; the runner evidence now records both (`environment.ci`). The
first CI run with these checks is the evidence for them, not this paragraph.

## What this does not show

- **No build attestation.** The SHA3 pins prove that the source bytes are the published ones, not who
  built the binary. There is no reproducible-build comparison by a second builder and no signature
  over the build. The builder itself writes `"approval": "NO_GO_LOCAL_BUILD_ONLY"`.
- **No deployment.** This is a CI process with `LD_LIBRARY_PATH`, not an installed runtime. The
  research's signed runtime-approval gate (`runtime_gate_v0711`) was not exercised with a real
  out-of-band key.
- **Version policy only.** "Patched" means "version ≥ 3.51.3 (and not 3.52.0)". It is not a proof
  that the WAL race cannot occur.
- **Local reproduction** was not possible from this maintenance environment, because the proxy
  refuses `www.sqlite.org`. A third-party copy of `sqlite3.c` (npm `better-sqlite3`, SQLite 3.53.4)
  failed the 3.54.1 pin and was not compiled. The GitHub runner is the only place this build ran.

## Kurzfassung (Deutsch)

In der CI wurde SQLite 3.54.1 aus der offiziellen sqlite.org-Amalgamation gebaut. Beide SHA3-Pins
wurden mit dem unveränderten Forschungs-Builder geprüft, und die Pins sind zusätzlich bei sqlite.org
gelistet. Es ist belegt, dass genau diese Bibliothek in die Testprozesse geladen wurde (Pfad,
SHA-256, Source-ID).

Darauf laufen alle 430 Tests als root ohne Skip. Die WAL-Reset-Sperre öffnet sich erstmals ohne
Override, auf der ungepatchten System-SQLite hält sie (Gegenprobe).

Offen bleiben die Build-Attestierung (signiert, reproduzierbar durch einen zweiten Builder) und der
reale Einsatz. Freigabe bleibt NO-GO.
