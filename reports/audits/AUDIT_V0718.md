# Equal3 v0.7.18 — Kritisches Architektur- und Sicherheitsreview

**Datum:** 25. Oktober 2026. **Entscheid:** **RESEARCH / NO-GO**. Referenz: v0.7.17 ZIP SHA-256 `1069d5bddb87ba4c5f884168ec245d0bfaeaed48374e31a36e907a2a5ad1c06b`. Keine produktive Freigabe; keine GitHub-Pushes.

## 1. Kritische Ausgangslage

v0.7.17 versiegelte Store-ID, Deployment und Attestierungsfingerprint mittels lokalem HMAC und sperrte willkürliche Änderungen. Es fehlte jedoch ein eigenständiges Root-autorisierbares **Rotationsprotokoll**. Mit Kenntnis des lokalen `seal_key` lässt sich die v0.7.17-`trust_binding`-Zeile samt lokal korrektem HMAC durch einen fremden Attestierungsschlüssel ersetzen. Die neue Negativkontrolle rekonstruiert die Akzeptanz durch v0.7.17. Eine lokale Versiegelung ist keine extern provisionierte Trust Root.

## 2. Implementierte Änderungen

- `trust_rotation_v0718.py`: Ed25519 Root/Attester Rollentrennung, strikte Root-Signatur über Store-ID/Deployment/alte und neue Schlüsselidentität, Epochensprung exakt +1, max. 300 Sekunden Autorisierungsfenster, strikt kanonische Felder.
- `RootControlledCASAnchor`: zusätzlicher HMAC-geschützter `root_binding` Datensatz; Prüfung im selben SQLite-Snapshot bei status/prepare/adjudicate; atomische Aktualisierung **beider** Trust-Tabellen; offene Commit-Intents blockieren Rotation; nach Commit ist alter Attestierer ungültig.
- Expliziter `min_epoch`-Parameter beim Öffnen. Ein echter unabhängig gespeicherter Wert kann einen lokalen Vertrauens-Rollback verhindern. **Die Version enthält keinen solchen externen Dienst.** `min_epoch=0` nach jedem Neustart ist unzulänglich.
- `anchor_wire.serve` ist bei attestiertem Betrieb standardmäßig root-pflichtig. Unsicherer v0.7.17-Betrieb ausschließlich über `research_unrooted=True` bzw. CLI `--allow-unrooted-research-only` (für synthetische Forschung, keine Deployment-Freigabe). Neue CLI-Parameter `--root-public-key-file`, `--trusted-min-epoch`.
- `rotate_attester_v0718.py`: Offline-Bedienpfad für bereits **extern signierte** Rotationszertifikate. Kein Root-Private-Key im Dienst. Expliziter Forschungs-Apply-Schalter; echte externe Epoch-Publikation bleibt Operations-Pflicht.

## 3. Negativkontrollen, Testnachweis

- v0.7.17: manipuliertes `trust_binding` mit neuem HMAC und fremdem Attestierer wird bei Kenntnis des seal_key akzeptiert.
- v0.7.18: dieselbe Manipulation wird bei **fest externer Root-Konfiguration** wegen zusätzlicher Root/Attester-Bindung verweigert. Root und Attester dürfen nicht derselbe Schlüssel sein.
- Root-Signatur falsch, andere Deployment-/Store-/Attester-ID, Überspringen/Replays von Epochen, ungültige Lebenszeit, Wechsel während pending Intent, zusätzliche/fehlende/tamperte Root-Zeile, alte v0.7.17-DB, fehlender Startup-Epoch-Floor -> HOLD bzw. Fehler.
- Injizierter SQLite-Abbruch zwischen den Trust-Updates: beide Änderungen werden zurückgerollt; nach Entfernen des Testtriggers funktioniert der autorisierte Übergang.
- Echter `AF_UNIX` RPC Status nach Root-Rotation/Neustart wird geprüft.
- **Explizit reproduzierbar:** Wird die alte Ankerdatei zurückkopiert und das externe Floor auf 0 zurückgesetzt, ist Rollback weiter akzeptierbar. Mit glaubwürdigem Floor 1 wird abgewiesen. Ein externer Floor ist derzeit **nicht vorhanden**.

## 4. Performance (synthetische Einzelabfrage)

Separater Interpreter pro Variante; vier ABBA-Runden, 40 Warmups plus 400 Statusabfragen pro Runde und Variante; gleiche Hardware. Grundgerüst der Quellcodedateien SHA-256-gebunden in Rohdaten.

| Modus | Median der 4 Durchlauf-Mediane |
|---|---:|
| v0.7.17 Attesterbindung | 0.255913 ms |
| v0.7.18 Root-Kontrolle | 0.273368 ms |
| Differenz | +6.8 % |

Kleine und verrauschte Stichprobe; **kein End-to-End-Commit- oder Multi-Host-Benchmark**. Selbst ein kleiner Overhead kann mit steigender Historie wachsen. P95-Rohmesswerte im CSV.

## 5. Noch offene P0 und Architekturkonsequenzen

1. Root-Public-Key und `min_epoch` müssen aus einem **separat verwalteten, authentifizierten, monotonen** Quellsystem kommen. Ein lokaler Kommandozeilenparameter oder eine zusammen rollbackbare Datei erfüllt dies nicht.
2. Das vorhandene `PersistentCASAnchor` und der explizite Legacy-Forschungsschalter bleiben im Source-Bundle; eine tatsächlich gesicherte Deployment-Konfiguration muss Downgrade-Pfade unterbinden und die Dienste organisatorisch/rechtlich trennen.
3. Root-Recovery und Root-Schlüsselwechsel selbst sind nicht implementiert; ein kompromittierter Root-Key ist ein eigener Notfallprozess. Für produktiven Betrieb: Zwei-Personen-Freigabe, M-of-N Threshold/dual-sign root updates, widerrufbare Key-Inventare, unabhängige Signierinstanz.
4. Beobachtungs-TOCTOU, Commit- und Anker-Doppelrollback, nicht manipulierbare Zeitquelle, SQLite 3.46.1, Hardware-/VFS-Powerloss, OS-MAC, Verschlüsselung, unabhängiger Pentest/DSG-Review bleiben offen.
5. Keine automatisierte Migration von v0.7.17: nachlässiger Rebootstrap könnte geschützte Historie vernichten.
6. CLI-Root-Verifikationsdatei und `min_epoch` sind Schnittstellen, kein Beleg externer Provenienz. Vor echter Migration: getrennte Instanz und auditierter Prozess mit systemgebundener Identität.

## 6. Extern abgeglichenes Wissen

- TUF Root-Rotation: Versionsschritt, Cross-Signatur durch alte/neue Root-Thresholds, Freeze-/Rollback-Verhinderung. Equal3 v0718 implementiert **nur** eine einfache, einseitig root-signierte Delegationsrotation, **keine TUF-konforme Root-Rotation**. https://theupdateframework.github.io/specification/v1.0.36/
- NIST SP 800-57 Part 1 Rev. 5: Key Lifecycle, kryptografische Rollentrennung, unabhängige Root Provisionierung. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- SQLite WAL-reset race und Patchstand: https://www.sqlite.org/wal.html

## 7. Reviewentscheidung

Der lokale Rotationsworkflow ist getestet und nachvollziehbar, aber keine unabhängig betriebene Vertrauenswurzel. **NO-GO für produktive Verwendung**. Größter nächster Hebel: realer KMS/HSM/externes monotones Epoch- und Commit-Register sowie formalisierte Root-Rotation mit unabhängiger Governance und Failover.
