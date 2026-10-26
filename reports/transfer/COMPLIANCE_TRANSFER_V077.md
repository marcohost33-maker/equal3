# Equal3 v0.7.7 – Matrixvorschlag (keine Änderung an aktiver Tabelle)

| Control | Thema | Befund | Maßnahme |
|---|---|---|---|
| EQ077-SQL-01 | Datenintegrität SQLite | 3.46.1 hat upstream WAL-Reset-Race-Risiko | patched runtime + Build-Attestation, GATE OPEN |
| EQ077-MAC-02 | Ankerintegrität | HMAC-Siegel lokal getestet | eigenständiges HSM/Key-Lifecycle ausstehend, PARTIAL |
| EQ077-LEGACY-03 | Altbestand | v076 authority ohne MAC nicht extern belegt | Migration nur nach independent attest, HOLD |
| EQ077-ISO-04 | Zugriff/Trennung | gleiche UID, gleiches OS im Test | OS ACL, separate Accounts, key vault, OPEN |
| EQ077-ENC-05 | Vertraulichkeit | Daten/WAL/SHM/Backups potenziell plaintext | etablierte AEAD/Datenträgerlösung, OPEN |
| EQ077-RET-06 | Logs | nonce/review log growth, user-linked digests möglich | Lösch-/Retentionkonzept, Datenminimierung, OPEN |
| EQ077-DSFA-07 | Schweizer DSG | synthetische Tests ohne Echtdaten | bei konkretem Hochrisiko-Einsatz DSFA prüfen, CONDITIONAL |

Referenzen: https://www.fedlex.admin.ch/eli/cc/2022/491/de ; https://www.edoeb.admin.ch/de/datenschutz-folgenabschaetzung ; https://www.sqlite.org/wal.html ; OWASP Storage.
