# === / Equal3 v0.7.8 – historisches Audit-Ledger versiegelt

**Stand:** 24.10.2026; **FREIGABE: NO-GO / Research Only**.

## Funktionalität und differenzierte Sicherheitsbehauptung

Das Authority-HMAC in v0.7.7 hat `authority` signiert, aber die Tabellen `consumed` und `review_log` nicht. Diese Forschungsfassung berechnet einen SHA-256-Root über die vollständigen, kanonisch sortierten Zeilen beider Protokolle. Der Root wird in derselben SQLite-Transaktion wie der Ankerzustand gespeichert und in die domain-separierte HMAC-Versiegelung einbezogen. Jede Statusabfrage prüft das Siegel und rekonstruiert den Root aus einem konsistenten SQLite-Snapshot.

- Positiv: Offline-Löschung, -Einfügung oder -Mutation protokollierter Nonces bzw. Freigaben wird bei intaktem, geheim gehaltenem Versiegelungsschlüssel erkannt.
- Negativ: Gemeinsames Zurücksetzen der gesamten DB plus Schlüssellage und Audit-Root bleibt möglich. Ein HMAC ersetzt weder externen monotonen Anker noch hardwaregestützte Signatur, Non-Repudiation oder Betriebssystemrechte.
- Migration: Frühere Authority-Dateien aus v0.7.6 oder v0.7.7 werden **nicht** automatisch übernommen. Upgrade setzt eine externe, unabhängige Zustandsattestation voraus.
- Skalierungsgrenze: Die sichere Vollprüfung liest O(n) historische Einträge pro `status()`/`prepare()`/`adjudicate()`. Eine zukünftige Checkpoint-/Merkle-Strategie braucht externe Root-Notarisierung sowie Prüfbeweise und wird nicht stillschweigend eingeführt.
- SQLite-WAL-Reset-Sicherheitsgate: unverändert strikt. Die in Tests explizit eingesetzte alte Runtime ist unsicher für Produktion.

## Nachprüfung

In einem **privaten, isolierten Testverzeichnis** mit synthetischen Daten, Python 3.13+, Unix/Linux:

```bash
python -Wa -m unittest discover -p 'test_*.py' -q
python -m unittest -q test_anchor_v078 test_release_preflight_v078
python release_preflight_v078.py  # erwartet Exit 2: NO_GO
sha256sum -c MANIFEST_V078.sha256
```

Der ursprüngliche v0.7.7-Negativtest-Beleg befindet sich unter `EVIDENCE_V078/negative_first_v077.log`, die komplette neue Regression und die isolierten Benchmarks daneben.

**Nicht ausführen** mit echten Personen-/Gesundheitsdaten, produktiven Schlüsseln oder auf unvertrauenswürdigen Host-/Filesystem-Konfigurationen.
