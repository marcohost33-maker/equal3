# CodeFactory Transfer — Equal3 v0.7.21

## Module und Übernahmebedingungen

| Kandidat | Source | Pattern | Tests | Nutzung / Einschränkungen |
|---|---|---|---|---|
| EQ3-CF-01 | `external_commit_witness_v0720.py:verify_final_checkpoint` | signiertes kanonisches Statement mit Domain-Separation | v0716/v0720 | Nur mit unabhängiger Signierrolle; kein Commit-Nachweis allein |
| EQ3-CF-02 | `external_commit_witness_v0720.py:publish` | CAS-Fortschritt mit HMAC-sealed head, strict v+1 | v0720, v0721 | Externes irreversibles Ledger fehlt |
| EQ3-CF-03 | `test_commit_floor_expiry_v0721.py` | Post-Lock signed evidence freshness | +2; negative-first | Keine verlässliche Zeitquelle; nicht als TOCTOU-frei vermarkten |
| EQ3-CF-04 | `EVIDENCE_V0721/expiry_falsification_probe.py` | separate Quellen, reproduzierbarer Red/Green Angriff | v0720->v0721 | CI nutzt exakte Quellhashes und erwartete Angriffserfolge |
| EQ3-CF-05 | `run_v0721_suites.py` / manifests | Split-suite & fail-closed evidence | 427 | Manifest ohne unabhängige Signatur; nur Paketkonsistenz |

## PRNR-/Gate-Schablone
`Finding_ID | Threat model | Provenance | Negative proof | Patch | Positive proof | Residual risk | Gate status | Reuse eligibility | Revalidation date`.

**Reuse Candidates:** Digi, Nigin, Insandbox, SafeForge, Hexa-NTK, Tool3D, AllScan. Zielrepo-Originalstände wurden nicht verändert. Lizenz/IP, Namespace, kryptographische Abhängigkeiten und Schutzansprüche vor jeder Übernahme separat prüfen.

**Do not copy:** Research-only unsafe overrides, Hard-coded test secrets, `MemoryCASAnchor` als Antirollback-Garantie, Core-Klassen ohne Witness-Enforcement.
