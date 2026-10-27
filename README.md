# Equal3 — research prototype for authenticated local state with external witnesses

![status](https://img.shields.io/badge/status-research%20%E2%80%94%20NO--GO-red)
![version](https://img.shields.io/badge/version-0.7.22--research-lightgrey)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![platform](https://img.shields.io/badge/platform-Linux%20%2F%20POSIX%20only-lightgrey)

> [!CAUTION]
> **Research only. Release decision: NO-GO. Not for production, not a security product.**
> Every audit round from v0.7.3 to v0.7.22 ended in NO-GO; the earlier lines were retrospectively
> classified as research only (see [docs/AUDIT_HISTORY.md](docs/AUDIT_HISTORY.md)).
> Open P0 items in v0.7.22 (from `reports/audits/AUDIT_V0722.md`, shortened):
> a truly independent, monotonic multi-host trust domain; the direct import/legacy bypass;
> unpatched SQLite 3.46.1 and its provenance; key KMS/HSM/rotation; commit/observer fencing
> and recovery; physical power-loss/ENOSPC/VFS tests; tamper-evident transparency-log
> consistency proofs; encryption including backups and journals; Swiss FADP (DSG) data
> inventory/retention/DPIA; an independent penetration test.
> The v0.7.22 audit did **not** complete the full suite (the multi-process `anchor_wire` group did
> not finish in the audit environment). A later Linux re-run on 2026-10-27 passed 430/430 as root
> from a byte-identical reconstruction of the bundle ([verification/2026-10-27_linux](verification/2026-10-27_linux/README.md)).
> That re-run comes from this repository's maintenance channel, not from an independent review,
> and it does not touch any open P0 item.

Equal3 (also written `===` in the sources) is a line of research code that started with
questions about minimal information ("how many bits does a state change really need?") and
grew into a study of **how a single host can prove that its local state was not rolled back**.
The finding repeated in every round: the local mechanisms built so far do not detect a joint
rollback of all local components (finding NR-01); an independent trust domain remains open.
This repository publishes the code, the tests, the per-round audits and the self-reported
evidence so that this result, and the techniques built along the way, can be inspected.

## What is in it — three layers

1. **Information minimisation (v0.1–v0.5).** A bounded, chunked, lossless state codec
   (`research/equal3.py`: RAW, ZLIB, XOR+ZLIB, SAME and SPARSE chunk modes, optional
   HMAC-SHA256 authentication), empirical entropy estimators (`research/info_theory.py`) and an
   educational one-instruction SUBLEQ machine with German step explanations
   (`research/minimalmaschine.py`).
2. **Authenticated state store (v0.6–v0.7.13).** `research/state_store.py`: SQLite store with
   version compare-and-swap, HMAC-chained receipts per request, authenticated reads and genesis
   binding; WAL mode or, since v0.7.13, `journal_mode=DELETE` with `synchronous=EXTRA`.
3. **Trust domain around the store (v0.7.2–v0.7.22).** External witness (`witness.py`), a
   guarded write facade (`guarded_store.py`), a two-phase anchor protocol with explicit HOLD
   verdicts (`anchor_protocol.py`), a sealed anchor service over AF_UNIX (`anchor_wire.py`),
   a separate-UID writer service (`writer_service_v0714.py`), a coordinated anchored writer
   (`anchored_writer_v0715.py`), signed commit observations and attester trust binding
   (`commit_evidence_v0716.py`), root-authorised rotation (`trust_rotation_v0718.py`), a live signed
   epoch witness (`external_epoch_witness_v0719.py`) and a signed commit-witness floor with
   post-lock expiry check and request-lineage binding (`external_commit_witness_v0720.py`,
   changed in v0.7.21 and v0.7.22).

## Version lineage

Test counts and findings are quoted from the audit of each round (self-reported; not re-run here
unless stated in [Local verification](#local-verification-of-this-import)).

| Version | Tests (reported) | Core idea | Main limit found | Verdict |
|---|---:|---|---|---|
| pre-history | – | Bit / minimal language (Brainfuck, SUBLEQ, ASCII) | one instruction type is not one bit | research |
| pre-history | – | Shannon / pixel (RGB24, entropy, context) | 24 bpp is representation size, not residual information | research |
| v0.1–v0.4 | – | Full, XOR, SAME, Sparse, Hash | a hash is no authenticator | research |
| v0.5 | – | blocks, HMAC, minimal machine, entropy | `tracemalloc` is not RSS | research |
| v0.6 | – | SQLite WAL FULL, version CAS, receipt | transaction boundary is a single SQLite DB | research |
| v0.7 | – | optimistic decoding, process-abort gates | 7 process aborts are not power-loss tests | research |
| v0.7.1 | – | verified online backup, SQLITE_FULL, WAL checkpoint | quota SQLITE_FULL is not OS ENOSPC | research |
| v0.7.2 | 77 | external witness prototype, 7 child-process abort points | joint rollback of DB + witness is not detected | research |
| v0.7.3 | 96 | GuardedStore, witness, receipts | historical receipt metadata not authenticated | NO-GO |
| v0.7.4 | 113 | HMAC receipt chain, consistent snapshots | only a local key; no external anchor | NO-GO |
| v0.7.5 | 139 | prepare/HOLD/review protocol | volatile in-process CAS test anchor | NO-GO |
| v0.7.6 | 167 | Unix-socket anchor daemon, SQLite durability | one UID, one failure domain | NO-GO |
| v0.7.7 | 176 | anchor HMAC seal, SQLite WAL policy | ledger metadata missing from the seal | NO-GO |
| v0.7.8 | 190 | authenticated historical audit rows | O(n) audit, hard limit 100k | NO-GO |
| v0.7.9 | 206 | DELETE/EXTRA anchor, UID socket test | state store still WAL; multi-host not attested | NO-GO |
| v0.7.10 | 219 | history-authenticated receipt/replay paths | O(n) replay cost | NO-GO |
| v0.7.11 | 240 | signed SQLite runtime approval, offline builder | no patched build actually deployed | NO-GO |
| v0.7.12 | 250 | authenticated `read`, genesis binding | O(n) read cost | NO-GO |
| v0.7.13 | 265 | optional DELETE/EXTRA state store | no automatically safe migration | NO-GO |
| v0.7.14 | 286 (groups) | separate-UID writer | old research API bypasses the anchor | NO-GO |
| v0.7.15 | 309 (groups) | coordinator writer → anchor | joint rollback still possible | NO-GO |
| v0.7.16 | 333 (groups) | separately signed post-commit observation | post-observation TOCTOU; no independent time | NO-GO |
| v0.7.17 | 347 (groups) | attester key/deployment persistently bound | seal key and DB rollback together | NO-GO |
| v0.7.18 | 375 (groups) | root-authorised rotation, monotone epoch | minimum epoch only local or caller-supplied | NO-GO |
| v0.7.19 | 401 (groups) | live signed epoch witness | no commit floor; shared rollback domain | NO-GO |
| v0.7.20 | 425 (groups) | signed commit floor, post-final signature | legacy bypass, witness rollback, observer window | NO-GO |
| v0.7.21 | 427 (groups) | expiry re-checked after the SQLite write lock | all P0 items external and open | NO-GO |
| **v0.7.22** | **29 focused** | witness floor bound to the committing `request_id` | full suite incomplete (`anchor_wire` timeout) | **NO-GO** |

Sources: v0.1–v0.7.2 from `reports/audits/EQUAL3_GESAMTAUDIT_2026-10-17.md` and
`reports/transfer/EQUAL3_LEARNING_TRANSFER_2026-10-17.md`; v0.7.3–v0.7.21 from the timeline table in
`reports/audits/AUDIT_GESAMT_V0721_2026-10-25.md`; v0.7.22 from `reports/audits/AUDIT_V0722.md`.
"(groups)" means the count is the sum of separately run test groups, not one monolithic run.

## Quickstart

Linux (or another POSIX system with `AF_UNIX`, `SO_PEERCRED`, `fcntl`) and Python 3.13 are
required. On Windows most test modules fail at import, because `anchor_wire.py` needs
`socketserver.UnixStreamServer`.

```sh
git clone https://github.com/marcohost33-maker/equal3.git
cd equal3
python3.13 -m venv .venv && . .venv/bin/activate
pip install -r research/REQUIREMENTS_RESEARCH_GATE.txt   # cryptography==46.0.4

# 1) Check that the imported files are byte-identical to the shipped research manifest
python tools/verify_provenance.py

# 2) Run all 12 test groups with a per-group hang limit (JSON evidence optional)
python tools/run_test_groups.py --expect-total 430 --json /tmp/equal3-groups.json

# or one group by hand (run from research/, the modules import each other flat)
cd research
python -B -W error::ResourceWarning -m unittest -q \
    test_commit_request_binding_v0722 test_external_commit_witness_v0720 test_commit_floor_expiry_v0721
```

Test groups as used in the v0.7.22 audit (module lists in [tools/run_test_groups.py](tools/run_test_groups.py),
the single source used by CI):

| Group | Modules | Reported count (v0.7.22 audit) |
|---|---|---:|
| witness (focused) | request binding v0722, commit witness v0720, expiry v0721 | 29 |
| equal | equal3, extensions, fault lab, guarded store, release preflight, rollback | 57 |
| store | store, v07, v071, v0710 security, v0712 integrity, v074 hardening, witness | 96 |
| runtime | runtime gate v0711, SQLite build v0711 | 21 |
| writer | writer service v0714 | 21 |
| coordinator | anchored writer v0715 | 23 |
| attester | attested commit v0716 | 24 |
| policy | attester policy v0717 | 14 |
| rotation | root rotation v0718 | 28 |
| epoch witness | external epoch witness v0719 | 26 |
| anchor base | anchor protocol, anchor v077, v078, v079 | 63 |
| anchor_wire | anchor wire (multi-process) | 28 (v0.7.21 run; did not finish in v0.7.22) |

The `anchor_wire` group starts helper processes and hung in the v0.7.22 audit environment. On Linux
it passed 10 of 10 repetitions in about 11 s on 2026-10-27, so CI runs it on every push and pull
request. Each group has a 300 s limit; a group over the limit is killed with its helper processes
and counts as a failure.

Four tests need root because they drop to a separate UID (writer v0.7.14 ×3, anchor socket v0.7.9
×1); without root they are skipped. CI therefore has two jobs: a normal one (430 run, 4 skipped)
and a root job that must run all 430 with no skip.

## Local verification of this import

Recorded on 2026-10-26 when this repository was assembled (details in the commit history):

- `sha256sum -c MANIFEST_V0722.sha256` on the unpacked bundle: rc 0; `tools/verify_provenance.py`
  maps all 382 bundle files and 23 supplementary files byte-identically.
- Test groups on **Windows** (Python 3.13.13, cryptography 46.0.4): the package is POSIX-only;
  10 of 11 groups fail at import, the store group partially runs. This is a platform result, not a
  defect claim.
- Test groups on **Linux** were not run locally for the import itself. The first CI run
  (2026-10-26, commit `4435627`) passed 11 groups (402 tests, 4 of them skipped for lack of root);
  `anchor_wire` was not run.
- **2026-10-27, Linux re-run** ([verification/2026-10-27_linux](verification/2026-10-27_linux/README.md)):
  flat bundle rebuilt from the mapping, `sha256sum -c MANIFEST_V0722.sha256` rc 0; all 12 groups
  **430/430 as root with 0 skips**, 430 run with 4 skipped as non-root; `anchor_wire` 10/10.
  Python 3.13.17, cryptography 46.0.4, SQLite 3.45.1. Same maintenance channel, not an
  independent review.

## Repository structure

```text
research/            Python modules, tests, runners and benchmarks of v0.7.22, flat as shipped
reports/
  audits/            per-round audit reports (German/English, as written)
  readmes/           per-version READMEs from the bundle
  roadmaps/          per-version roadmaps
  release-gates/     per-version release-gate JSON (all NO_GO)
  transfer/          compliance and CodeFactory transfer notes
  misc/              environment, isolation design, test summary
evidence/
  v0.7.4-v0.7.5/ … v0.7.22/   per-version evidence folders (logs, CSV/JSON, patches)
  fresh-zip-reruns/  rerun logs of the delivered zips (from the 007acc2 knowledge folder)
  manifests/         MANIFEST_V0722.sha256, historical manifests, PATH_MAPPING.tsv
verification/        later re-runs of the imported tree (not part of the import)
docs/                audit history, roadmap, threat model, ADR, path mapping
tools/               verify_provenance.py, run_test_groups.py (+ tests)
```

The original bundle was flat. Files were moved into these folders without changing a byte; see
[docs/PATH_MAPPING.md](docs/PATH_MAPPING.md).

## Limitations (what is explicitly not protected)

Summarised in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). The most important:

- **NR-01 joint rollback.** If the state store, the anchor and the commit witness are restored
  together to an older valid set, the older position is accepted again. No local mechanism here
  prevents that.
- **Legacy bypass.** Older research APIs (`StateStore.apply`, older writers) remain importable and
  bypass the witness gate.
- **No trusted time.** Expiry checks use the local wall clock.
- **Unsigned manifests.** SHA-256 manifests show internal consistency only, not authorship.
- **No confidentiality.** Store, journals, snapshots and backups are plaintext.
- **No hardware fault evidence.** Process-crash tests are not power-loss, torn-write or ENOSPC tests.

## Test material

All keys in this repository are synthetic test material and must never be used productively:
fixed HMAC test keys such as `b'K'*32` or `b'Test-only shared secret 32+ bytes - change before
deployment!'`, and Ed25519 keys generated at test run time. No private key files are included.

## Provenance and authorship

Equal3 is research by **Coworker Research / Coworkerz**. The code, tests, evidence and audit
reports of v0.7.3–v0.7.22 were produced in iterative research rounds in the 007acc2 cross-family
review channel, whose assignment files are addressed to GPT-6 ("GPT-6-Sol"), a model family
different from the one that assembled this repository. The Equal3 files themselves do not name
the model.
The audit reports call themselves independent re-audits, but they were produced in the same
channel; **no external third-party security review has been performed** (it is an open P0 item in
every round). This repository was assembled from those artefacts with Claude Code; the research
content was not changed.

## Citation

See [CITATION.cff](CITATION.cff). Please cite the version and state the NO-GO status.

## License

Apache License 2.0, see [LICENSE](LICENSE).

---

## Kurzfassung (Deutsch)

Equal3 ist ein **Forschungsstand mit Freigabeentscheid NO-GO** — nicht für Produktion, kein
Sicherheitsprodukt. Der Code untersucht, wie ein einzelner Host beweisen könnte, dass sein lokaler
Zustand nicht zurückgesetzt wurde: Informationsminimierung (Bit/Shannon/Delta), ein
authentifizierter Zustandsspeicher (SQLite, CAS, HMAC-Quittungen) und eine Vertrauensdomäne aus
externem Zeugen, attestiertem Writer, Rotation, Commit-Floor und Request-Lineage. Das zentrale
Ergebnis jeder Runde: Ein gemeinsamer Rollback aller lokalen Komponenten wird nicht erkannt (NR-01).
Im v0.7.22-Audit wurde die vollständige Testsuite nicht abgeschlossen. Eine spätere Linux-Nachfahrt
am 2026-10-27 aus dem byte-identisch rekonstruierten Bundle ergab als root 430/430 ohne Skip, und
`anchor_wire` lief 10 von 10 Mal durch. Sie stammt aus demselben Wartungskanal, ist also keine
unabhängige Prüfung. Seither laufen `anchor_wire` und eine root-Lane in jeder CI. Alle Audits liegen im Original unter `reports/audits/`.
