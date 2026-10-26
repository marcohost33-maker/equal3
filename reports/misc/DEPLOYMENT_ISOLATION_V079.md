# Equal3 v0.7.9 – Betriebskonzeption, NICHT deployed

**Zweck:** Die in Tests nachgewiesene Zweit-UID-Erreichbarkeit des Ankerdienstes auf einen Host mit nichtprivilegierten Dienstkonten übertragen. Dieses Dokument ist ein Entwurf, **keine ausgeführte Infrastrukturkonfiguration**.

## Lokale Berechtigungsstruktur (Beispiel)

| Pfad | Eigentümer | Gruppe | Modus | Zweck |
|---|---|---|---|---|
| `/var/lib/equal3-anchor` | `equal3-anchor` | `equal3-anchor` | `0700` | Ankerdatenbank + Journal + Seal-/Reviewer-Key |
| `/var/lib/equal3-anchor/authority.db` | `equal3-anchor` | `equal3-anchor` | `0600` | Eigenständiges SQLite-DELETE-Journal |
| `/run/equal3-anchor` | `equal3-anchor` | `equal3-writer` | `0710` | Nur Traversal der dedizierten Gruppe |
| `/run/equal3-anchor/anchor.sock` | `equal3-anchor` | `equal3-writer` | `0660` | Unix-RPC, zusätzlich `SO_PEERCRED` exakte Writer-UID |
| `/var/lib/equal3-state` | `equal3-writer` | `equal3-writer` | `0700` | Datenbank des StateStore, getrennt von Anchor |

Beide UID/GID-Konten müssen lokal vom Administrator erstellt werden. Ein zuständiger Orchestrator startet die Dienste mit enger Prozess-Isolation, kontrolliert Socket-Group-Chown-Fähigkeit, Schlüsselbereitstellung und umask. Der Ankerprozess darf nicht dieselbe UID wie der Writer besitzen. `--writer-gid` aktiviert die absichtlich restriktive Gruppenkonfiguration. Die Autorisierung der RPC-MACs erfolgt zusätzlich, nicht statt `SO_PEERCRED`.

Ein Dienst mit ankerprivatem Verzeichnis darf **nicht** dieselben Backup-Mounts oder Admin-Zugänge nutzen wie untrusted Writer. Der Root/Host-Bedrohungsraum bleibt davon ausgenommen; dafür ist eine wirklich separate Vertrauensdomäne erforderlich.

## Abnahme-Negativproben

1. Writer-UID erreicht Socket und kann `status()` mit gültigem Writer-MAC ausführen.
2. Writer-UID kann DB, Reviewer-Key, Seal-Key und Journaldatei nicht öffnen; `ptrace`, Proc-Env, Core-Dumps und Backups müssen gesondert ausgeschlossen sein.
3. Fremde UID erreicht den Socket nicht; falls dennoch zugänglich, lehnt `SO_PEERCRED` sie ab.
4. Modus-Downgrade 0710→0770/0777 oder Gruppendrift verhindert Dienststart.
5. `-wal`/`-shm`/Formatänderung am Authority-File führt zu HOLD ohne automatische Umstellung.
6. Nach Prozessabbruch bleiben korrekte alte oder neue transaktionale Zustände; tatsächlicher Stromausfall bleibt bis VFS-Lab unbelegt.
7. Externer Anker und Monitoring melden Host-/Snapshot-Fork. Ohne getrennte Domäne kein Anti-Rollback-GO.

**Noch nicht ausgeführt:** realer systemd-Deploy, Account-Lifecycle, SELinux/AppArmor, seccomp, externe KMS/HSM, echte Recovery auf anderen Maschinen.
