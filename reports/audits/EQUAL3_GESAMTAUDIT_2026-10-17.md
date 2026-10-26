# === Equal3 — kritisches Gesamtaudit (2026-10-17)

## Anspruch und Prüfgrenze
Review des Chatverlaufs (Theoriebasis und Code-Releases v0.1–v0.7.1), lokale Quellen v0.1–v0.7.1 und v0.7.2, Regression, Prozess-Faults, Witness-Tests, Quellenvergleich. **Kein** E2E-Sicherheitsnachweis und keine Komplettinspektion anderer Produktlinien.

## Historische Evidenz
| Linie | Geliefert | Korrigierte Interpretation |
|---|---|---|
| Bit / minimal language | Brainfuck, SUBLEQ, ASCII | One instruction type != one bit; Semantik hängt von Zustand/Grammatik ab |
| Shannon / Pixel | RGB24, Entropie, Kontext | 24 bpp ist Darstellungsgröße, nicht mittlere Restinformation; Codec-Datenrate umfasst Kontext/Overhead |
| v0.1-0.4 | Full, XOR, SAME, Sparse, Hash | Kompression nicht immer hilfreich; Hash ist kein Authentifikator; Wort 'validiert' gilt nur für Tests |
| v0.5 | Blöcke, HMAC, Minimalmaschine, Entropie | Speicherzahl tracemalloc != RSS; Blockierung, Offlineprozesse, Vorhersageressourcen offen |
| v0.6 | SQLite WAL FULL, Versions-CAS, Quittung | Transaktionsgrenze ist eine einzelne SQLite-DB; keine systemübergreifende oder rollbacksichere Transaktion |
| v0.7 | Optimistische Decodierung, Prozessabbruch-Gates | 7 Prozessabbrüche sind NICHT VFS-Powerloss-Tests; No-op performance claims without context |
| v0.7.1 | verified Online Backup, SQLITE_FULL und WAL Checkpoint | quota-SQLITE_FULL ist nicht OS-ENOSPC; Backup kann alt, plaintext oder orphaned sein |
| v0.7.2 | external witness prototype, seven child-process abort points | detects rollback only if witness+secret survive in separate trust domain; joint rollback demonstrably bypasses |

## PR / NR (Positive / Negative Results)
PR-01: Kombiniertes Zustand+Quittung-Commit in SQLite 77 Regressionstests einschließlich der übernommenen Tests und neuer Prüffälle bestanden.
PR-02: Separater Versionszeuge detektiert DB-Rollback bei festgehaltenem signiertem Zeugen.
PR-03: Seven process-crash sites produce internally consistent old-or-new state/receipt outcomes on tested platform.
PR-04: Signed witness rejects key mismatch, malformed/noncanonical payload, rollback, version fork and unanchored updates.
NR-01: Gemeinsamer Rollback von DB und signiertem Zeugen **wird nicht erkannt**. This is expected and tested.
NR-02: Gleichheitszustände sind kein Beweis gegen Replay; identical payload with new version must be separately accounted for.
NR-03: No physical power-loss/torn-sector emulation, independent pin, archive encryption or semantic pixel codec executed.
NR-04: Entropy estimator cannot by itself set a universally optimal codec; compute cost and headers can dominate.

## Mathematische Bausteine
- Shannon-Entropie: H(X) = -sum_i p_i log2(p_i)
- Bedingte Entropie: H(Y|X) = H(X,Y)-H(X)
- Mutual information: I(X;Y) = H(Y)-H(Y|X)
- Bit-Tiefe: bpp = channels * bits_per_channel (uncompressed packed representation)
- Sparse delta length (fixed): L ~= L_header + k * (address_bits + value_bits)/8; variable gaps improve it but require header/range validation.
- CAS: commit iff expected_version=actual_version and base_digest matches.
- Authenticated proposal: MAC = HMAC(K_domain, domain || canonical_header || packet)
- Witness: signed tuple (store_ID, version, digest); requires separate trust boundary.
- Cost vector: C=(bits, encode_time, decode_time, peak_RSS, energy, assurance/risk); Pareto comparison only under same conditions.
- Bayes false-negative: P(signal|negative)=P(negative|signal)P(signal)/P(negative).

## Security finding register (fail-closed)
| ID | Severity | Finding | Gate |
|---|---|---|---|
| EQ-P0-01 | Critical | Plaintext snapshots/backups, no at-rest secrecy | approved encryption/keys, threat model, access control, data minimization |
| EQ-P0-02 | Critical | Missing independently enforced monotonic anchor | external protected witness, crash-gap reconcile, anti-rollback attest |
| EQ-P0-03 | High | No VFS torn-sector/out-of-order hardware error simulation | SQLite test VFS/APSW/C harness with isolated temp volumes |
| EQ-P0-04 | High | No long-running coverage-guided fuzz and external pen-test | fuzz corpus, coverage, independent security reviewer |
| EQ-P0-05 | High | Key lifecycle/rotation/revocation absent | NIST SP800-57 key identifiers and cryptoperiod policy |
| EQ-P1-06 | Medium | Orphan backup temp file after crash; leaks plaintext | restricted temp parent and controlled GC + retention |
| EQ-P1-07 | Medium | Encoder RAM/CPU vs bit-savings not optimized | multi-objective benchmark with RSS/energy monitoring |
| EQ-P1-08 | Medium | Unlimited growth receipts; metadata can identify actors | finite retention vs replay safety/compaction policy |
| EQ-P1-09 | Medium | Store is single BLOB up to 8 MiB | content-addressed chunk manifest w/ atomic commit |
| EQ-P2-10 | Low | Pixel codecs not implemented | spatial/channel predictors versus PNG, JXL, zstd |

## Workflow / Methods / Templates
Requirements→Threat model→Invariants→Positive/negative test oracle→Mutation/Fault injection→Reproduction→Source/provenance review→Gate decision. Gate thresholds must be pre-registered; report P50/P95, N, host, CPU/RSS and full wire size. Never relabel partial-process crash tests as actual powerfail. Release with deterministic SHA256 manifest and provenance, no GitHub push without user approval.

## Hard boundaries
Status = RESEARCH; no production claim. v0.7.2 is an **additive** witness and fault-lab module preserving old codec and DB formats. It is not a full custom VFS implementation or an independent review of SQLite internals.

## Validated external sources
https://sqlite.org/testing.html ; https://www.sqlite.org/vfs.html ; https://sqlite.org/atomiccommit.html ; https://sqlite.org/backup.html ; https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final ; https://www.fedlex.admin.ch/eli/cc/2022/491/en ; https://www.edoeb.admin.ch/en/information-security ; https://www.rfc-editor.org/rfc/rfc8878.html ; https://www.rfc-editor.org/rfc/rfc9659.html
