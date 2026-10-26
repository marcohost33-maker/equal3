# Compliance-Transfer — Equal3 v0.7.21

**Matrix:** `02_Datenschutz_Compliance_Matrix` / Blatt `Equal3_Audit_2026-10-25`. Separater aktualisierter Operations-Workbook-Tab und Lernstatistik. Keine Aussage über tatsächlich verarbeitete personenbezogene Daten ohne produktives Datenfluss-Inventar.

## Kontrollfamilien
1. **CH DSG Art. 6/7** — Zweck, Minimierung, Privacy by Design/Default; Request-IDs und Bezeugungsmetadaten auf Personenbezug prüfen.
2. **CH DSG Art. 8** — angemessene technische/organisatorische Datensicherheit: Key Roles, Verschlüsselung DB/journals/backups, Rechte/Protokollierung, Widerruf.
3. **CH DSG Art. 22/23** — Risikoscreening/DSFA, bei hohem verbleibendem Risiko Konsultationsprüfung.
4. **CH DSG Art. 24** — dokumentierte Reaktion auf Verletzungen der Datensicherheit einschließlich Meldefrist-Logik nach Sachverhalt.
5. **NIST 800-57 / RFC 9162 / OWASP** — Rollen- und Schlüssellebenszyklus, unabhängige signierte Konsistenzbeweise, sensitive data log minimization.

## Eintragungen und Grenzen
Die Registerzellen sind Arbeits-/Risikoübertragungen und stellen keine rechtsanwaltliche Zertifizierung dar. Eigentümer, genaue Verarbeitungszwecke, Löschfristen, Speicherorte, Auslandsbekanntgabe, Auftragsverarbeiter und DSFA sind nach realem Deployment zu bestimmen. Production NO-GO bleibt für fehlende independent trust, gepatchte SQLite und Enforcement bestehen.
