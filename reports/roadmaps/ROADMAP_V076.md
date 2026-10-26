# Equal3 v0.7.6 — priorisierte Roadmap mit Abnahme-Orakeln (2026-10-24)

Alle P0-Gates bleiben **OFFEN**, soweit keine unabhängige Zielumgebungsattestierung vorliegt. `PROTOTYPE_PASS` != Release.

| Rang | Kernrisiko | Nächste Implementation | Unverzichtbares Abnahme-Orakel |
|---|---|---|---|
| P0-A | Zwei Datenbanken = gemeinsame Rücksetzbarkeit | HSM/KMS/TPM-gebundener oder anderer administrativ getrennt betriebener monotoner Trust-Service mit unabänderbaren Auditankern | Nach unabhängigen Neustarts/Restore-Angriffen ist **jedes** Rollback- und Fork-Szenario fail-closed; verlorener Anker darf nie auto-genesis auslösen |
| P0-B | Gleiche OS-UID im Test | Eigener schreibberechtigter Dienst-User, eigener Datenträger/Volume, untrusted Client hat keinerlei Pfad-/FD-/Key-Zugriff; Systemd-Berechtigungen und POSIX-ACL-Test | Positiv-/Negativkontrollen gegen unprivilegierte Zugriffe, Bind-/Symlink-Races, geteilter Storage, Proc-FDs, Backups; Zielhost nachweisen |
| P0-C | Commit-Nachweis stammt vom Client | Authentifizierter, unabhängiger Evidence-/Attestation-Dienst und manualisierte 2-Personen-Recovery für unbestimmte Zustände | Unterzeichnete Quelle und SQLite-Commit-Receipt an derselben Request-ID; gezielte gefälschte und verspätete Evidence wird abgelehnt |
| P0-D | Localhost-RPC-Limits | Authenticated mutual TLS für entfernten Backendbetrieb, ACL und PKI-Rotation, Security-Test des Serverprotokolls | End-to-end Verbindung, Rekey/Revocation, replay, downgrade, truncation, DoS, abruptes Netzende, injizierte Latenz |
| P0-E | Daten im Klartext | Bewährte at-rest-Lösung für SQLite-Daten, WAL, SHM, Temp, Backups, Snapshots und Crash-Dumps; KEK/DEK-Lifecycle | Test gegen Offline-Dump, Wiederherstellung, Schlüsselrotation, Entsorgung, Log-/Backup-Leak; DSFA falls angezeigt |
| P0-F | Fehlende Powerloss-Evidenz | SQLite C-VFS Fault-Lab und separates VM-/Filesystem-Testlabor (fsync, ENOSPC, torn, reorder) | Wiederholbarer Seed+Fault-Corpus; alte oder neue zulässige Transaktion, niemals stiller illegaler Zustand; maschinenlesbare Fault-Matrix |
| P0-G | Release Governance | Externer Security-Review + Threat-Model + Reproducible SHA-bound Build | Eigenständige Reviewinstanz, signierte Befunde, Owner-Go, genaue Artefaktidentität und schriftliche verbleibende Risiken |
| P1-A | Verifikationskomplexität O(n) | Versionierte, vom Anker signierte Checkpoint-Struktur + konsistente Snapshots | Falsifikation historischer Manipulationen bleibt bestehen; End-to-end-Nachweis auf langen Logs; P50/P95/P99 mit N>=1000 |
| P1-B | Nonce-/Receipt-Wachstum | Begrenztes Log, nachvollziehbare Audit-Archivierung und deduplizierte Nonces mit Zeitfenstern/Generation | Kein Wiederholungs- oder Fork-Fenster durch Pruning, kein DoS durch unendliches Wachstum |
| P1-C | Cross-host Portabilität | Plattformadapter Windows/macOS, echter Kernel-Peercred-/ACL-Vergleich | Exakte Fähigkeiten pro OS; fail-closed bei fehlender Peer-Verifikation |
| P1-D | Formale Eigenschaften | TLA+ oder Apalache Modell: Safety und Liveness getrennt | State-Space-Counterexamples dokumentiert, Provenance des Modells und Spec-Review |
| P2 | Informationstheorie / Bildcodec | Fairer Paket-/Laufzeit-/RSS-/Energievergleich gegen PNG, JPEG XL, zstd | Gleicher verlustfreier Korpus; komplette Header- und Indexkosten; Qualitäts-/Validierungsnachweise |

**Nächster sinnvoller Meilenstein:** P0-A + P0-B in einer **separaten Test-VM**, mit positivem und negativem Test auf die effektive Vertrauensgrenze. P0-C danach an eine unabhängige Evidence-Quelle anbinden. Keine weiteren behaupteten Produktiv-Freigaben auf Basis lokaler Simulatoren.
