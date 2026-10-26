# Equal3 0.7.16 – Compliance-Transfer (kein produktives Matrix-Update)

Empfohlene Einträge für die aktive DSG-/Compliance-Matrix, deren schreibende Änderung hier ausdrücklich NICHT erfolgt:

- `EQ16-COMMIT-EVIDENCE-PARTIAL`: Ed25519-signiertes Commit-/Abort-Statement und Reviewer-HMAC im Forschungsbackend; keine unabhängige Infrastruktur.
- `EQ16-EVIDENCE-STALE-P0`: Gegenbeispiel: DB-Rollback nach korrekt signiertem Snapshot; Anker kann anschließend trotz altem DB-Zustand finalisieren.
- `EQ16-ANCHOR-ROOT-P0`: Persistente behördliche DB und Schlüssel sind noch gemeinsam rücksetzbar; externe Monotonie und unabhängiges Trust-Root fehlen.
- `EQ16-SUPPLY-CHAIN-P0`: SQLite 3.46.1; gepatchte signierte Laufzeit fehlt.
- `EQ16-KEYS-DSG-P0`: Schlüsselrotation, HSM-/KMS-Betrieb, Wiederherstellung, Verschlüsselung inkl. Backup, Betroffenenrechte und Datensparsamkeit nachprüfen.
- `EQ16-RESEARCH-ONLY`: ausschließlich synthetische Daten und Schlüssel; keinerlei produktiver Einsatz.

Benötigt: Data-flow-Map, Rollen und Zugriffsrechte, Risikofolgenabschätzung falls erforderlich, Retention-/Löschregeln, Datenschutz-Verantwortung mit Schweiz-DSG und ggf. kantonalem Recht. Kein juristisches Freigabeurteil.
