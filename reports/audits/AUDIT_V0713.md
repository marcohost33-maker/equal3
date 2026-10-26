# Equal3 v0.7.13 – kritisches Review und Implementierungsnachweis

**Datum:** 25. Oktober 2026  
**Ausgangspunkt:** original archivierte v0.7.12-Quellfassung / 250 dokumentierte Tests.  
**Entscheidung:** **RESEARCH / NO-GO**. Keine produktiven Systeme modifiziert.

## 1. Verifikation der Ausgangslage

Das aktive Python 3.13.5 lädt SQLite **3.46.1**. Die SQLite-Dokumentation beschreibt einen
WAL-Reset-Race, der bei gleichzeitigen WAL-Schreib- oder Checkpoint-Zugriffen mehrerer
Datenbankverbindungen unter sehr speziellen Timingbedingungen Datenbankkorruption
verursachen kann. Der Fix ist in 3.51.3 enthalten, mit offiziellen Backports 3.44.6 und
3.50.7. Upstream 3.54.1 ist die aktuell verifizierte Version vom 16.10.2026.

Official upstream references:
- https://www.sqlite.org/wal.html
- https://www.sqlite.org/pragma.html#pragma_synchronous
- https://www.sqlite.org/atomiccommit.html
- https://www.sqlite.org/download.html

Der Versuch, das offizielle SQLite-3.54.1-Amalgamationsarchiv direkt in dieser
isolierten Umgebung zu beziehen, scheiterte an Zugriffsbeschränkungen. Der offizielle
SHA3-256 der ZIP-Datei lautet:
`92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`.
**Keine gepatchte SQLite-Version heruntergeladen, kompiliert oder eingebunden.**

## 2. Architekturentscheidung

Ein alternativer, explizit ausgewählter StateStore-Betriebsmodus `journal_mode=DELETE`
mit `synchronous=EXTRA` wurde implementiert. Durch Vermeidung des WAL-Modus entfällt
die spezifische Eintrittsbedingung des WAL-Reset-Race für DIESE Datenbank. Dies
macht SQLite 3.46.1 nicht allgemein fehlerfrei oder den Betrieb produktionsreif.

Die Implementierung verwendet nur statisch zugelassene `WAL`/`DELETE`-Moduswerte,
vermeidet automatische Umstellung, prüft beim Öffnen von DELETE-Stores zuerst den
SQLite-Header (Read-/Write-Version 1/1), verweigert WAL-Sidecars, Symlink-Dateipfade
und unpassende Journalpolitik. Der neue Modus setzt pro Verbindung `EXTRA` und
verifiziert numerisch `3`. Backup überprüft den gespeicherten Modus, CLI-Befehle
akzeptieren `--journal-mode DELETE`. WAL-Checkpoint wird auf DELETE-Stores abgewiesen.

**Grenze:** Die Header-/Sidecar-Prüfung ist kein atomarer `openat2()`-Pfadschutz;
bei einem feindlichen Same-UID-Writer oder kompromittiertem Host bestehen
Dateiaustausch-Rennen. Nur OS-eigene Rechte einer separaten Writer-Identität,
Schlüsseltrennung, echte vertrauenswürdige Laufzeit und Hardware-/VFS-Faulttests
könnten die Produktionsfreigabe stützen.

## 3. Regressionen und gezielte Falsifikationen

Die vollständige Suite wurde im finalen Quellstand mit
`python -W error::ResourceWarning -m unittest discover -s . -p 'test_*.py' -q`
ausgeführt: **265/265 PASS**, 62.855 Sekunden. Davon **15 neue Tests** gegenüber der
dokumentierten v0.7.12-Linie mit 250 Fällen. `ResourceWarning` wird als Fehler behandelt.

Die neuen Tests decken ab: `DELETE`-Datenbankheader, `EXTRA`-Sync, `apply/read/receipt`,
Version-CAS bei konkurrierenden Prozessen, optionaler CLI-Modus, Restore und Backup,
WAL-Header-Falsifikation *vor* normalem SQLite-Connect, Sidecar- und Symlink-Blockaden,
Explizite Ablehnung der Gegen-Journalpolitik, abgebrochene Transaktion und `os._exit`
vor/nach Commit. Letzteres ist Prozessausfall-Simulation, **kein** physischer Powercut.

Die bestehenden 250 Tests arbeiten weiterhin im ursprünglichen Forschungs-WAL-Modus.
Ihre Resultate sind keine Belege für die Unbedenklichkeit des dortigen SQLite-Builds.

## 4. Vergleichsbenchmark – Einschränkungen

ABBA/Mikrobenchmark innerhalb derselben v0.7.13-Codebasis mit jeweils neuen temporären
Stores, Nutzlasten 1024 und 65536 Byte. 4 Runden je Nutzlast, pro Modus 6 Warmups
und 30 gemessene `apply()`/`read()`-Operationen. `prepare_update()` lag außerhalb
des zeitlich gemessenen `apply()`-Fensters. Mediane der vier Run-Mediane:

| Nutzlast | Operation | WAL/FULL | DELETE/EXTRA | Verhältnis DELETE/WAL |
| --- | --- | ---: | ---: | ---: |
| 1 KiB | `apply` | 2.037 ms | 2.121 ms | 1.04x |
| 1 KiB | `read` | 0.597 ms | 0.547 ms | 0.92x |
| 64 KiB | `apply` | 2.850 ms | 2.422 ms | 0.85x |
| 64 KiB | `read` | 0.739 ms | 0.636 ms | 0.86x |

Interpretation: innerhalb des lokalen Single-Client-Mikrobenchmarks keine massive
Leistungsstrafe. **Kein** Nachweis besserer Parallelität, Haltbarkeit bei Stromausfall,
Durchsatz, p99 unter Last oder reproduzierbarer Vorteil auf anderen Betriebssystemen.
Rohdaten und Skript: `EVIDENCE_V0713/journal_benchmark.csv` und
`benchmark_v0713_journal.py`.

## 5. Was weiterhin offen ist

1. **P0: gepatchte SQLite-Laufzeit** in allen produktiven Pfaden oder vollständig
   kontrollierte DELETE/EXTRA-Policy mit unabhängiger Sicherheitsabnahme.
2. **P0: mandatory writer service** unter getrennten Unix-Konten mit exklusivem
   Datenbank-/Key-Zugriff und kryptografisch gepinnter Runtime-Startfreigabe.
3. **P0: externer nicht rücksetzbarer Anker, Commit-Attestation** und getrennte
   Verwaltungsdomäne; gemeinsamer DB+Anker-Rollback weiterhin nicht aufdeckbar.
4. **P0: Verschlüsselung, Backups, Temp-Dateien, Löschung, Datenschutz/DSFA.**
5. **P0: echte VFS-Fehler, ENOSPC, torn writes, Stromausfall, Backups und Recovery.**
6. **P1: authentifizierte Checkpoints** gegen die linearen O(N)-Kosten der HMAC-Historie.

Ein grüner Teststand oder ein lokales Hashmanifest ist **keine** Signatur, keine
Abnahme durch einen unabhängigen Gutachter und keine Produktionsfreigabe.
