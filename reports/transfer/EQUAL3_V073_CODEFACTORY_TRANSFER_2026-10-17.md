# === v0.7.3 — wiederverwendbare Module für CodeFactory
Scope: nur geprüfte lokale Referenzmodule, kein GitHub-Push und kein integrierter CodeFactory-Produktionsbuild.

## Wiederverwendbare Bausteine
1. `GuardedStore` (neues Modul): Fail-closed gate vor/ nach `StateStore.apply` unter Advisory-Lock; WARNUNG: ungeschützte Raw-API darf im Produkt nicht erreichbar sein.
2. `witness.Checkpoint`: kanonischer, domain-separierter HMAC-Checkpoint mit Version/Store-ID/Digest; Signaturwort vermeiden, es ist symmetrischer MAC.
3. `state_store.verify`: eine konsistente SQLite-Read-Transaktion mit Metadaten/Quittung/Key-Binding.
4. `guarded_store.diagnostics`: reine Diagnose ohne Auto-Heal; `AHEAD_OF_WITNESS_HOLD` statt automatischer Korrektur.
5. `test_guarded_store`: 19 unabhängige Negativ-/Konkurrenztests; darunter echte Subprozesse, No-Op-Replays, Pre-/Postcommit-Fehler.
6. `benchmark_guard`: synthetische P50/P95-Messung mit eindeutigem Nenner und offengelegtem Workload.
7. Die existierenden Module: `equal3`, `info_theory`, `minimalmaschine` für getrennte Codec-/Semantik-/Entropie-Experimente.

## Technische Integrationsgates
- Keine untrusted APIs direkt auf `StateStore.apply`.
- Eigene Trust-Domain und monotoner externer Anchor verpflichtend, wenn Anti-Rollback versprochen wird.
- Manueller, nachvollziehbarer Recovery-/Adjudikationsprozess nach unbestimmtem Commit.
- Vollständig reproduzierbarer Build, Quellcode-SHA, Tests, unabhängige Security Review.
- Kein `assert` als Produktions-Gate; explizite Fehlerklassen und negative Tests.
- Codelizenz / Herkunft des Originalmoduls separat prüfen, bevor Teile in fremde Repos übertragen werden.
