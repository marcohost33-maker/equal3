# Equal3 0.7.17 — Datenschutz- und Governance-Übertrag

Die im separaten ZIP hinzugefügte `trust_binding` ist eine lokale Policy-Bindung. Keine DSG-Freigabe; keine Änderungen an einer aktiven Compliance-Matrix in diesem Schritt. Als Einträge für die spätere zentrale Matrix vorgemerkt:

- EQ17-POLICY-PIN: Public-Key/Deployment/Store-ID/Seal; Forschung PASS.
- EQ17-ROOT: Externe Root-of-Trust-Provisionierung/Persistenz/Revocation: P0 OFFEN.
- EQ17-DATA: personenbezogene Daten, Schlüssel-/Log-Metadaten, Zugriff und Löschung: P0 OFFEN vor produktivem Einsatz.
- EQ17-AUDIT: Unabhängiges Audit-Log mit unveränderbarer Retention und Exportkontrolle: P0 OFFEN.
- EQ17-LIB: Gepatchtes SQLite + Runtime-Provenienz: P0 OFFEN.

Schlüsseldateien, persönliche Daten und vertrauliche Betriebslogs sind nicht Bestandteil des Artefakts. Die Testschlüssel sind synthetisch, nicht produktiv zu nutzen.
