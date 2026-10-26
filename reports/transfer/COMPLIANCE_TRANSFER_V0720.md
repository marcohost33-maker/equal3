# Equal3 v0.7.20 – Transfer zur Compliance-Matrix, noch NICHT in die aktive Matrix geschrieben

- Schutzbedürftige Artefakte: Statuswerte/Digests/Request-IDs können sensible Metadaten offenlegen (Frequenz, Korrelation). Retention/Minimalprinzip, Access-Control und sichere Löschung müssen bewertet werden.
- Getrennte Rolle für Signing Key, HMAC-Seal Key, Observer und Writer. No-key-in-argv; private Schlüssel mit getrennten Eigentümern und Rotation/Revocation.
- CH DSG: Verzeichnis/Verarbeitungszweck, Datensparsamkeit, rollenbasierter Zugriff, grenzüberschreitende Speicherung, Löschkonzept, incident response; nur Vorbereitung, noch keine juristische Freigabe.
- Externe Protokoll-Zeugen können wiederum personenbezogene Digest-Metadaten speichern; Geografie und Auftragsdatenverarbeitung sind vor Test mit Echtdaten abzuklären.
- SHA-256-Manifest ist kein Provenienznachweis. Signierte Artefakte/SBOM, reproducible build, unabhängige Versorgungskette noch offen.
- P0 NO-GO: gemeinsamer Zeugenrollback, Stale Post-Final-Attestation, alte Writer-Bypass-Pfade, SQLite 3.46.1, hardwareseitige Nachweise und unabhängige Prüfung.
