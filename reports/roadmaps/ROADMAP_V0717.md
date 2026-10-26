# Equal3 v0.7.17 — Priorisierte Roadmap

| Gate | Ziel/Abnahmebeweis | Zustand |
|---|---|---|
| G0 Attester-Pinning | Neuer Anker erzwingt HMAC-versiegeltes Public-Key/Deployment/Store-ID-Binding auch nach Restart; Negativtests | Forschung IMPLEMENTIERT |
| G1 Root Provisioning P0 | Anker-Verifikation root-/KMS-provisioniert, attestierter Policy-Bootstrap und kontrollierte Reviewer-Key-Isolation; kein Legacy-Downgrade | OFFEN |
| G2 Trusted External Witness P0 | echter unabhängiger nicht gemeinsam rücksetzbarer monotoner Anker mit End-to-End-Commit-Nachweis | OFFEN |
| G3 Commit TOCTOU P0 | Signiertes Evidence kann nicht nach DB-Rollback stale eingesetzt werden; reproduzierbarer Adversarial-Hardwaretest | OFFEN |
| G4 SQLite Runtime P0 | tatsächlich eingebundener, gepatchter SQLite-Build mit SHA3/source-ID und Binary Provenance | OFFEN |
| G5 Isolation/Encryption P0 | Writer OS-MAC, AuthN/AuthZ, Verschlüsselung aller Journale/Backups, Keys rotierbar | OFFEN |
| G6 Safety/QMS P0 | Power-Cut/VFS-Failure, unabhängiger Audit, Datenschutz-DSFA, Release-Signoff | OFFEN |
| G7 Performance P1 | 10k/100k Transaktionen, P50/P95/P99, RSS, Audit-Authentifizierung statt unsicherem Cache | OFFEN |

**Nächste Reihenfolge:** Trust-Domänen getrennt bereitstellen -> attestierte Schlüssel/Boot-Policy -> echter nicht-rücksetzbarer Zeuge -> formaler 2-Phase Recovery-Pfad -> gepatchtes SQLite+VFS-Labor -> Release-Prüfung.
