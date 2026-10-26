# Equal3 0.7.16 — unabhängige Commit-Beobachtung (Forschungs-Audit)

**Datum:** 25.10.2026. **Freigabe:** `RESEARCH / NO_GO`. Ausgangspunkt ist das unveränderte, lokal verfügbare v0.7.15-Bündel; keine produktiven Systeme oder GitHub-Repositories wurden verändert.

## 1. Kritische Prüfung der beiden vorherigen Reaktionen

Die v0.7.14- und v0.7.15-Antworten dokumentierten korrekt den `NO_GO`-Status, die HMAC-authentifizierte Quittungshistorie, den expliziten `HOLD`-Zustand und die Linux-UID-/Socket-Grenze. Der entscheidende blinde Fleck blieb **an der Ankerbehörde**: Die Prüfbehörde kannte bisher nur einen Reviewer-HMAC und einen passenden vorbereiteten Intent. Sie forderte **keinen unabhängig signierten Nachweis über den tatsächlich beobachteten DB-Commit**. Der Koordinator prüfte die DB lokal, aber ein direkter Aufruf der Anker-API konnte diese Prüfung umgehen.

### Falsifikation des v0.7.15-Ankers

1. Authentifizierte synthetische V2-Datenbank bei Version 0, persistente Ankerbehörde mit `DELETE/EXTRA`.
2. Einen gültigen Intent vorbereiten, **keinen** SQLite-Commit ausführen.
3. Den HMAC-Review-Token für `FINALIZE_COMMIT` präsentieren.
4. Original `PersistentCASAnchor.adjudicate()` akzeptiert die Finalisierung: Anker Version 1, SQLite weiterhin Version 0. **Das ist ein bewiesener fehlerhafter Freigabepfad bei vorhandener Reviewer-Autorisierung ohne Commit-Evidenz.** Ein Angreifer ohne Review-Schlüssel kann das nicht alleine ausführen; der Nachweis betrifft ungenügende Bindung des Review-Entscheids an die DB-Tatsache.

## 2. Implementierte Änderungen

**`commit_evidence_v0716.py`:** Neuer obligatorischer Attestierungsmodus `EvidenceRequiredCASAnchor`. Neben dem bisherigen Reviewer-Token ist ein Ed25519-signiertes Statement nötig. Es bindet Domain, Deployment-ID, Intent-SHA-256, Request/Version/Digest (über den Intent), beobachtete DB-Version/Digest, Presence/Absence des authentifizierten Receipts, Entscheidung, separate Beobachtungs-ID und kurze Gültigkeitsdauer (maximal 60 Sekunden).

**`issue_observation()`:** Referenz-Implementierung für eine ausdrücklich **gesonderte** Inspektor-Rolle; prüft `StateStore.inspect_request()` (ganze authentifizierte V2-Historie, kohärenter Snapshot), den Anker-Intent und das passende Commit-/Abort-Ergebnis vor Signierung. Die Beispielsignierung läuft in synthetischen Tests, **nicht** unter einem nachweislich unabhängigen Schlüsseldienst.

**`anchor_wire.py`:** RPC-Protokoll kann die zusätzliche Evidenz transportieren. Start-CLI verlangt standardmäßig eine root-provisionierte Ed25519-Öffentlichschlüsseldatei plus Deployment-ID; ein ungebundener Ankerstart muss ausdrücklich als `--allow-unattested-research-only` bezeichnet werden. Alte Forschungs-Socket-Fixtures sind nur mit dieser expliziten Ausnahme ausführbar. Beim normalen Start wird vor `socket.bind` abgewiesen. Keine produktive Freigabe durch die CLI allein.

**`anchor_protocol.py`:** `CoordinatedStore.adjudicate(..., evidence=...)` unterstützt die zusätzliche behördenseitige Prüfung, ohne einen automatischen Reviewer/Signierer einzuführen.

**Negativ-/Positiv-Tests:** Der unzulässige Legacy-Freigabepfad wird reproduziert; im neuen Modus lehnt der Anker HMAC-only ab. Positiv geprüft sind signierter Commit, signierter Abort, Live-RPC-Übertragung, Restart, Replay, falscher Schlüssel, falsche Deployment-ID, manipulierter Digest, abgelaufene/zu frühe Signaturen, falscher Review-HMAC und fehlende Felder.

## 3. Kritische verbleibende Gegenbeispiele und Grenzen

1. **Stale Evidence / Race:** Selbst eine ehemals korrekte, signierte Beobachtung ist nicht unveränderlich wahr. Wird die lokale DB *nach* der Signierung zurückgesetzt, kann die behördenseitige Entscheidung auf dem alten Beleg beruhen. Der neue Gegenbeispieltest zeigt ausdrücklich, dass der Anchor trotz erneuter DB-Version 0 auf Version 1 fortschreiten kann. Anschließende Diagnose erkennt `ROLLBACK_HOLD`; das ist nicht dasselbe wie präventiver Schutz vor dieser Race. Nur unabhängig beobachtete, irreversibel attestierte Commit-Evidenz mit gegenzeitlicher Sperre kann das lösen.
2. **Unabhängigkeit:** Der Testsignierer, der DB-Key und die lokalen Dateien sind hier unter derselben administrativen Kontrolle. Domain-Trennung, root-provisionierter Trust-Pfad und signierte Zeitquelle sind nicht operativ abgenommen.
3. **Downgrade/Legacy:** Der alte `PersistentCASAnchor` bleibt zur Testkompatibilität im Paket und kann bei Kenntnis seiner Schlüssel direkt geöffnet werden. Die echte Unmöglichkeit eines Downgrades braucht getrennte OS-Rechte, persistente Policy-Bindung und externe Anker-Attestation. Der neue Standard-CLI-Zweig ist konservativ fail-closed, aber das ist kein Hardwareschutz.
4. **Zeit:** Gültigkeitsdauer nutzt die lokale Unix-Uhr, keine monotone, abgesicherte Behördenzeit.
5. **SQLite/Hardware:** Python-Umgebung SQLite 3.46.1; `DELETE/EXTRA` meidet den WAL-Race-Pfad des neuen StateStore-Modus, ersetzt aber nicht den gepatchten, unabhängig belegten Build oder VFS-/Powerloss-Tests.
6. **Vertraulichkeit/Compliance:** DB/Journale/Backups noch nicht durchgängig verschlüsselt; keine verpflichtende Schlüsselrotation, Revocation, DSG/DSFA- oder unabhängige Freigabe.

## 4. Tests und Performance

Die sieben unabhängigen Testgruppen einschließlich 24 neuer Sicherheitstests werden mit `-W error::ResourceWarning` ausgeführt. Der Abschlussstatus und die Einzel-Lane-Logs liegen in `EVIDENCE_V0716/suite_summary.json`. Positive und negative Fälle sind im Code nachzuvollziehen. **Keine** Behauptung einer monolithischen End-to-End-Testfreigabe oder einer realen unabhängigen Signing-Domäne.

Synthetischer ABBA-Vergleich in gleicher Laufzeit mit 4 Sweeps, 25 gemessenen Commit-/Review-/Retry-Transaktionen je Kombination plus Warmup. Keine echte Reviewer-Latenz und kein externer Netzwerkhop:

| Nutzlast | Review-HMAC allein | Review-HMAC + Ed25519 Beobachtung | Mehrkosten |
| --- | ---: | ---: | ---: |
| 1 KiB | 18,671 ms | 21,848 ms | +17,0 % |
| 64 KiB | 20,327 ms | 23,478 ms | +15,5 % |

Die Werte sind Mediane der vier Sweep-Mediane, **keine SLA, kein Konfidenzintervall**. Benchmark-Rohsamples: `EVIDENCE_V0716/benchmark_attestation_abba.csv`.

## 5. Fachgrundlagen

- RFC 8032 EdDSA/Ed25519: https://www.rfc-editor.org/rfc/rfc8032
- RFC 8785 zur Notwendigkeit deterministischer Kodierung: https://www.rfc-editor.org/rfc/rfc8785 (unser enges String/Integer/Bool-Format beansprucht **keine** vollständige RFC-8785-Konformität).
- OWASP Schlüsselrolle, Key-Lifecycle, unabhängige private Signer: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- SQLite Release History / WAL-Reset-Fix: https://www.sqlite.org/changes.html

## 6. Entscheidung

**`NO_GO`.** Diese Runde implementiert eine nachprüfbare zusätzliche Autorisierungshürde unmittelbar vor dem CAS-Anchor-Finalize. Ein wirklich unabhängiger Signier- und Speicheranker mit nicht gemeinsam rücksetzbaren Zuständen, starker Commit-Observation, gepatchtem SQLite-Build und physischem Fehlerlabor bleibt P0 OFFEN.
