# === / Equal3 v0.7.6 — Persistent Local Anchor Research (24.10.2026)

**Status:** RESEARCH ONLY — **NO-GO for production**. Dies ist ein Quellcode- und Testprototyp, keine produktionsreife Anti-Rollback-Lösung.

## Gegenstand

Version 0.7.6 erweitert das v0.7.5-Referenzprotokoll um `anchor_wire.py`:

1. Separate SQLite-Ankerdatenbank mit monotonem Compare-and-Swap innerhalb einer lokalen Trust-Annahme. WAL + `synchronous=FULL`, `BEGIN IMMEDIATE` und persistierte Pending-Intents.
2. Separater Unix-Domain-Socket-Prozess mit HMAC-authentifizierten RPC-Nachrichten (Request und Response), `SO_PEERCRED`-UID-Check auf Linux, Nonce-Replay-Ledger für mutierende Methoden und 16-KiB-Nachrichtengrenze.
3. Manuelle, intent- und entscheidungsgebundene Reviewer-Freigabe, deren Geheimnis **nicht** durch den RPC-Dienst ausgestellt wird.
4. Fail-closed bei Neustart mit fehlender Ankerdatenbank, ungültigen Tokens, konkurrierenden Versionsübergängen, unterbrochenem Commit und unerreichbarem Dienst.
5. Reproduktion durch 28 zusätzliche Unit-/Integrationstests und einen ABBA-Mikrobenchmark.

**Strikte Grenze:** Die Prüfdatei des Ankers liegt im Prototyp weiterhin auf dem gleichen Host mit der gleichen administrativen Rücksetzbarkeit. Weder ein Same-UID- noch ein Root-/Host-Kompromiss ist ausgeschlossen. Es gibt keinen KMS-/HSM-Sicherheitsanker, keine Zielplattform-ACL-Attestierung, keine Verschlüsselung von DB/WAL/Backups und keinen SQLite-C-VFS-Stromausfalltest.

## Ausgangsdaten und Versionierung

Ausgangspunkt: `EQUAL3_v075_ANCHOR_PROTOCOL_RESEARCH_2026-10-24.zip`. Die existierenden Codecs, Datenbankformate und Tests bleiben erhalten. Das bisherige `anchor_protocol.py` bleibt als instabiler Simulations-/Client-Referenzteil unverändert; der neue Dienst implementiert dessen `status/prepare/adjudicate`-Schnittstelle. **Kein GitHub-Push, kein Merge, kein Deployment.**

## Wiederholbare Tests

```sh
python -m unittest discover -p 'test_*.py' -v
python -m unittest -v test_anchor_wire
python bench_anchor_v076.py EVIDENCE_V076
sha256sum -c MANIFEST_V076.sha256
```

Die Tests erzeugen getrennte, kurzlebige Datenbanken und 32-Byte-Testschlüssel in privaten temporären Verzeichnissen. **Niemals echte Daten oder produktive Schlüssel verwenden.**

Die vollständigen lokalen Testausgaben und Messdateien liegen unter `EVIDENCE_V076/`. Das Batch-Mikrobenchmark misst `apply` plus gesonderte `FINALIZE_COMMIT`-Freigabe. Proposal-Encoding, Dienststart, Remotenetz, Festplattenausfallszenarien und physischer Powerloss werden nicht gemessen.

## Lokaler Dienst (nur Test/Referenz, keine Installationsanleitung für Produktion)

- Ankerdatenbank **einmalig** per `PersistentCASAnchor.bootstrap(path, Position(...), reviewer_key=...)` aus *nachprüfbar attestierter* Genesis anlegen. Dieser Quellstand gibt kein automatisches Bootstrap beim Start frei.
- Dienst mit `python anchor_wire.py --db <path> --socket <path> --writer-key-file <path> --reviewer-key-file <path> --writer-uid <uid>` starten. Schlüsseldateien müssen rohe 32-Byte-Inhalte und Modus 0600 besitzen, ihre unmittelbaren Verzeichnisse Modus 0700. **Im Test läuft alles unter derselben UID; dies ist keine starke Isolation.**
- Test-/Referenzclient mit `RPCAnchor(socket_path, writer_key=...)` und `CoordinatedStore(store, anchor)` verbinden.
- Reviewer-Signatur als HMAC nur aus einer **separat verwalteten Instanz** erzeugen, auf Grundlage des exakt geprüften Intents, der SQLite-Quittung und der freizugebenden Entscheidung. Die Demo generiert Tokens nur in Testfixture/Microbenchmark; der Dienst stellt keine `sign`-Methode bereit.
- Nach SIGTERM ist ein normaler Dienststopp möglich. Nach SIGKILL kann der Socketpfad noch existieren; niemals blind entfernen, bevor PID, Pfadtyp, Eigentümer, Prozesszustand und gesichertes Recovery überprüft sind.

## Protokoll / Recovery

`MATCH -> PREPARED -> [SQLite COMMITTED_PENDING | NOT_COMMITTED] -> REVIEW -> MATCH`

Ein offener Intent setzt weitere Änderungen aus. `FINALIZE_COMMIT` ist nur bei vollständig nachgeprüftem Commit und passender Quittung erlaubt. `ABORT_NOT_COMMITTED` ist nur ohne Commit und ohne entsprechende Quittung zulässig. Ungewisser Zustand bleibt `HOLD`. Der Ankerdienst prüft die DB **nicht selbst**; der angebundene Client führt die Diagnose durch. **Eine manipulierbare Client-Bescheinigung ist kein unabhängiger Commitbeweis.**

## Verifikationsmatrix (präzise)

- **Belegt:** atomarer lokaler Anker-CAS, Neustartpersistenz, Peer-UID-/HMAC-/Nonce-Eingangsprüfung, Negativproben, Fail-Closed-Ergebnisse, synthetische Latenzen.
- **Falsifiziert:** gemeinsames Zurücksetzen beider SQLite-Dateien ist weiterhin möglich und kann alte gültige Zustände erscheinen lassen.
- **Nicht belegt:** hardwaregestützte Nicht-Rücksetzbarkeit, produktive Mandantentrennung, echte Attestation des SQLite-Commits, untrusted Clients mit unzugänglichem Raw-Writer, verschlüsseltes Datenleben, VFS-/Storage-/Netzwerkfehlerrobustheit, unabhängige Sicherheitsfreigabe.

Lies vor Integration `AUDIT_V076.md`, `ROADMAP_V076.md`, `RELEASE_GATES_V076.json` und `COMPLIANCE_V076.md`.
