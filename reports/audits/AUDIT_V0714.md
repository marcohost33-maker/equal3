# Equal3 v0.7.14 – kritisches Audit und Entwicklungsnachweis
**25.10.2026 | Referenz:** Equal3 v0.7.13 Research | **Entscheidung:** NO-GO.

## 1. Ausgangslage / negative architecture findings
Original v0.7.13 besitzt `StateStore.apply()` und eine CLI mit direktem Zugriff auf Datenbank und Schlüssel. Allein die Absicht einer geschützten Writer-API beweist keine OS-Isolation. Die vorhandene lokale SQLite-Bibliothek ist 3.46.1; laut https://www.sqlite.org/wal.html ist diese alte WAL-Linie von einer potentiellen Race-Korruption betroffen. Version 3.54.1 (16.10.2026) wurde recherchiert, aber nicht eingebaut. DELETE/EXTRA reduziert lediglich den spezifischen WAL-Risiko-Pfad.

## 2. Änderung
`writer_service_v0714.py` implementiert einen begrenzten, authentisierten Linux Unix-Socket-Dienst. Client verlangt keinen StateStore-Key und übermittelt keine selbst signierte Datenbanktransaktion; der isolierte Dienst erstellt den Equal3-Vorschlag und führt ihn aus. Er benötigt ausdrücklich:
- eine andere `writer_uid` als die Dienst-UID;
- Service-DB und 32+-Byte-Secret als eigentümerkontrollierte Dateien (`0600`) und privates DB-Verzeichnis (`0700`);
- dedizierte Socket-Gruppe/Verzeichnis (`0710`) und überprüfte Socket-Rechte (`0660`);
- Linux `SO_PEERCRED`; Rahmenlimit 8 MiB, Lese-Timeout, maximal acht gleichzeitige Client-Slots;
- `StateStore` im `DELETE/EXTRA`-Modus, voll authentifizierte HMAC-Receipt-Historie;
- signierte gepatchte Laufzeit-Freigabe und externen root-provisionierten Ed25519-Public-Key.

**Zusätzliche P0-Sperre:** Da kein unabhängiger CAS-Trust-Anker an den neuen Writer gebunden ist, verweigert die öffentliche `serve`-Routine regulären Betrieb (`P0 independent anchor ... HOLD`). Positivtests verwenden ausschließlich `_research_unanchored=True` als interne Testinjektion und Mock-Freigabe. Diese Ausnahme ist NICHT über die CLI zugänglich. Die CLI verweigert zudem Root-Betrieb. Ein passender produktiver Anker und eine real attestierte SQLite-Laufzeit sind nicht vorhanden.

## 3. Sicherheitsinvarianten
- **Single owner:** Der Client benötigt weder Datenbank noch Master-Key; keine Übergabe des StateStore-Objekts über RPC.
- **Stable idempotency:** Wiederholung mit derselben Request-ID/Ziel-Digest = bereits bestätigte Quittung, kein zweiter Commit. Andere Ziel-Daten mit derselben ID -> Replay/HOLD.
- **Linearized writes:** Zugriff auf StateStore unter einem Mutex; SQLite-Version-CAS ist zweite Linie.
- **Bounded input:** Framing und Zustandsgröße werden vor großen Leseoperationen geprüft; unvollständige Frames/fehlender Peer werden zurückgewiesen.
- **Startup fail-closed:** Keine automatische Migration, keine unbestätigte SQLite-Laufzeit, kein produktives Öffnen eines ungebundenen Ankers.
- **No trust-domain overclaim:** Gleichzeitiger Rollback und Root-/Host-Kompromittierung weiter möglich.

## 4. Reproduzierbare Tests
- **265/265 bestehende Tests erfolgreich** in vier separaten Python-Testprozessen: 91, 57, 94, 23 Tests; `-W error::ResourceWarning`.
- **21/21 neue Writer-Tests erfolgreich**, darunter reelle Linux-Uids 0 und 65534; Unix-Socket-Schreibvorgang gelingt, privater Key-Zugriff aus der Client-UID schlägt fehl, falsche Client-UID wird abgewiesen.
- Testfall zeigt, dass eine manipulierte historische Quittung beim erneuten Commit eine `IntegrityError` auslöst.
- **Einschränkung:** Ein monolithischer Ein-Prozess-Gesamtlauf wurde wegen Timeout **NICHT** als bestanden gewertet. Batches liefern ergänzende Evidenz, aber nicht denselben Nachweis wie ein monolithischer Lauf mit gemeinsamen Prozess-/Ressourceneffekten.
- Positive Runtime-Gate-Annahme in OS-Isolationstest ist **simuliert** und nicht mit echter 3.54.1-Laufzeit oder externer Signatur verwechselt.

## 5. Performance
ABBA-Order (direct/core/core/direct), 2 Größen und je 24 measured iterations pro Round, 5 warmups, neue TempDB/Sequenz je Round. `SET` Wrapper (`WriterCore`) vs direkte lokale `prepare_update`+`apply`, **ohne Socketkosten**:

| Nutzlast | Direkt, Median der Round-Mediane | WriterCore, Median der Round-Mediane | Unterschied |
|---|---:|---:|---:|
| 1 KiB | 2,768 ms | 3,204 ms | +15,8 % |
| 64 KiB | 3,690 ms | 4,255 ms | +15,3 % |

Kein Konfidenzintervall und kein produktionsähnlicher Parallel-/IPC-Test. Die Mehrkosten sind real in diesem Experiment, nicht allgemeingültig.

## 6. Offene Risiken und Priorität
1. **P0:** Unabhängiger monotoner Anker + Signierung externer Commit-Attestation + Crash-Reconcile; Writer über eine solche Coordinator-API anbinden.
2. **P0:** Tatsächlich gepatchte SQLite-Bibliothek mit SHA3-Quellnachweis und unabhängiger Ed25519-Freigabe im gestarteten Betrieb, nicht nur Testmock.
3. **P0:** Realer nichtprivilegierter Dienst-User, separate Client-UID, Systemdienst und OS-MAC/Sandbox, reproduzierbare ACL-/Restore-Tests; sicherstellen, dass direkte DB/key-Zugriffe im Produkt ausgeschlossen sind.
4. **P0:** Encryption-at-rest, Schlüsselverwaltung, Backups/Retentionskonzept und DSFA bei sensitiven Informationen.
5. **P0:** Fault-Injection über VFS + echte Powercut/Torn-Write, unabhängiger Pentest.
6. **P1:** Socket-Latenz P50/P95/P99 unter Last, Langzeitressourcen, Rate-Budgets, Watchdog, backpressure, attestierte Checkpoints und Ein-Prozess-Suite-Hänger untersuchen.

## 7. Quellen
- SQLite: https://www.sqlite.org/wal.html ; https://www.sqlite.org/pragma.html#pragma_synchronous ; https://www.sqlite.org/news.html
- SO_PEERCRED: https://man7.org/linux/man-pages/man7/unix.7.html
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- systemd Isolation: https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml

**Kein GitHub-Push/Merge/Deploy**, keine aktive Compliance-Matrix verändert, keine nicht verfügbaren Produktionsnachweise behauptet.
