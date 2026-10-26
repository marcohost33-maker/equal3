# Equal3 v0.7.18 — Vorschlag Datenschutz- und Compliance-Matrix

- `EQ0718-01`: Root-/Attester-Rollen sind getrennt; private Root-Schlüssel **dürfen nicht** im Writer/Anker-Container liegen. P0 offen: unabhängige Verwaltung und MFA/2-Personen-Freigaben.
- `EQ0718-02`: Epoch-Floor muss von einem antirollback-fähigen Dienst kommen, nicht aus dem DB-Volume/CLI. P0 offen.
- `EQ0718-03`: Rotation erzeugt sicherheitsrelevante Logs: minimiere darin Request-IDs/Personendaten, schütze Log vor Zugriff, definiere Fristen und Zweck. P0 Policy/DSFA bei Personendaten.
- `EQ0718-04`: Notfallplan bei verlorenen/kompromittierten Root-Schlüsseln, Rekey/Recovery/Widerruf, Rechtezuordnung. P0 offen.
- `EQ0718-05`: Research-Only-Schalter muss in Produktion technisch verboten werden (Deployment-Gate/OS Policy). P0 offen.
- `EQ0718-06`: Keine testweise Verwendung realer personenbezogener Daten; in dieser Runde nur synthetische Datensätze.

**Status:** Vorbereiteter Wissenstransfer, keine Mutation einer bestehenden aktiven Matrix, keine Rechtsberatung.
