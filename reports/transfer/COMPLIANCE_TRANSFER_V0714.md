# Equal3 v0.7.14 – Compliance Transfer (Entwurf, nicht in aktive Matrix eingetragen)
- `EQ0714-DATA-ISOLATION`: nur isolierter Test nachgewiesen; Benutzer-/Gruppenzugriff im produktiven OS fehlt.
- `EQ0714-KEY-CUSTODY`: Master-Key bleibt lokal in Dienstspeicher und 0600-Testdatei; Vault, Rotation, Revocation und Zeroization offen.
- `EQ0714-REPLAY`: Client kann stabilen Request-ID-Token senden; Digests/Quittungen stellen Metadaten dar, die bei personenbezogenen Daten ebenfalls Schutzbedarf besitzen können.
- `EQ0714-APPROVAL`: signiertes Laufzeit-Gate in Referenz implementiert, aber produktiver Signer und gepatchte SQLite-Laufzeit fehlen.
- `EQ0714-ROLLBACK`: weiterhin kein unabhängiger monotoner Anker und kein external commit attestation, RELEASE HOLD.
- `EQ0714-RETENTION`: Protokoll-Aufbewahrung, Löschzweck, technische Datenminimierung und Datenschutz-Folgenabschätzung je Einsatzprofil zu prüfen.
- `EQ0714-RESTORE`: unabhängige Backup- und Notfall-Wiederherstellungsnachweise fehlen.

Schweiz: DSG-konforme Rollen-/Risikoanalyse, allfällige DSFA nach Art. 22 DSG bei hohem Risiko. Keine Rechtsfreigabe erklärt.
