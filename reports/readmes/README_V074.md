# === / Equal3 v0.7.4 — gehärtete Forschungsversion (24.10.2026)

**Status: RESEARCH ONLY / PRODUKTIONSFREIGABE: NO-GO.** Das ZIP ist ein nachvollziehbares, testbares Entwicklungsartefakt, kein Deployment-Paket für personenbezogene oder sicherheitskritische Echtdaten.

## Gegenstand

Dies ist eine **additive Forschungsfortführung** des Originalpakets `EQUAL3_V073_GUARDED_STORE_VERIFIED_2026-10-17.zip` (SHA-256 `027bdcb5c2074cab90049ffa1a0a100ea4c8ff776d174d5acc0e5ecfc0ecbcf7`). Alle vorhandenen Testfälle bleiben erhalten; die ursprüngliche ZIP-Datei wird nicht überschrieben.

Neue Implementierungen in `state_store.py`, `witness.py`, `guarded_store.py`:

1. **V2-Quittungskette für neu angelegte SQLite-Stores:** `receipt_auth` mit HMAC-SHA256 über sequenzierte Quittungen, storegebundene Schlüsselableitung und initialen State-Digest. Quittung und Authentifikator werden in **derselben SQLite-Transaktion** geschrieben. Das HMAC schützt gegen nachträgliche Änderung einzelner Quittungen durch Akteure **ohne** den geheimen Schlüssel, solange der Chain-Head vertrauenswürdig ist.
2. **Historische Feldvalidierung** für V1 und V2 (Typen, Version, ID-/Hashlänge); V1-Bericht explizit `LEGACY_UNSEALED`. Eine V1-Historie wird **nicht** automatisch kryptografisch attestiert oder migriert.
3. **Kohärente Prüfung und Leseansicht** via `StateStore.read_verified()` und `GuardedStore.read()`; Lesen und Audit kommen aus einer einzigen gepinnten WAL-Lesetransaktion. Die Witness-Gleichheit gilt für genau diesen Snapshot, nicht gegen spätere unkooperative Änderungen.
4. **Gezielte Pfadhärtung:** Witness-Lesen mit `O_NOFOLLOW`, Dateityp-/Größenbegrenzung, Lock-Datei mit `O_NOFOLLOW`, Eigentümer-/Modusprüfung; nur POSIX und vertrauenswürdiger lokaler Dateisystemkontext.
5. **Direkte Raw-Schreibprüfung:** Bei V2 wird im Schreibtransaktionskontext die letzte HMAC-Quittung geprüft, bevor eine neue Kette fortgesetzt wird. Die vollständige historische Kette wird weiterhin beim `verify()` geprüft; ein Raw-Writer kann den Witness prinzipiell umgehen.
6. **Testhygiene:** Offene SQLite-Verbindungen in übernommenen Testhilfen explizit geschlossen. 17 neue adversarielle/negative Tests, darunter 250 deterministische mutierte Vorschläge.

## Reproduzieren

```bash
python3 -m unittest discover -p 'test_*.py' -q
python3 -m compileall -q .
sha256sum -c MANIFEST_SHA256.txt
```

Zuletzt gemessen: Python 3.13.5, SQLite 3.46.1, Linux 6.18.55, **113/113 Tests**, **86 % kombinierte Statement-/Branch-Coverage** der sechs Kernmodule. Test-/Benchmark-Logs stehen unter `EVIDENCE/`. Der Branch-Coverage-Wert ist ein aggregierter Werkzeugbericht, **kein** Vollständigkeitsbeweis.

## API-Minimalbeispiel (synthetische Daten)

```python
import secrets, tempfile
from pathlib import Path
from state_store import StateStore, prepare_update
from guarded_store import GuardedStore
import witness

with tempfile.TemporaryDirectory() as d:
    base = Path(d)
    anchor_dir = base / 'trust'
    anchor_dir.mkdir(mode=0o700)
    key = secrets.token_bytes(32)
    wkey = secrets.token_bytes(32)
    db = StateStore.create(base / 'state.sqlite', key=key, initial=b'A')
    anchor = anchor_dir / 'witness.bin'
    witness.initialize(db, anchor, wkey)
    guarded = GuardedStore(db, anchor, wkey)
    guarded.apply(prepare_update(db, b'B')[0])
    assert guarded.read().value == b'B'
    assert db.verify()['receipt_auth'] == 'HMAC_CHAIN_V2'
```

Dieser lokale Witness bleibt ein **Demonstrationsanker**, kein externer monotoner Dienst.

## Verbindliche Sicherheitsgrenzen

- Ohne **separate, nicht gemeinsam rücksetzbare Trust-Domain** gibt es **keinen** starken Anti-Rollback-Nachweis; ein gemeinsames Rücksetzen von Datenbank, HMAC-Witness und erhaltenem Schlüssel bleibt möglich.
- SQLite und lokaler Witness haben **keinen atomaren gemeinsamen Commit**. `AnchorPendingError` setzt den Schreibpfad auf HOLD; Recovery benötigt dokumentierte, externe Adjudikation.
- `GuardedStore` ist weiterhin eine **kooperative Python-Fassade**; direkter Zugriff auf `StateStore.apply()` ist technisch möglich. Produktive Kapselung erfordert Betriebssystem-Isolation, alleinigen Writer-Service, Berechtigungstrennung und nicht exportierte Master-Keys.
- Der produktive Live-Store, SQLite WAL/SHM, Backups und Temp-Dateien sind **nicht** verschlüsselt. Niemals echte sensible Daten unter diesem Status speichern.
- Nicht getestet: unabhängige VFS-Powerloss-/Torn-Write-Faults, reales Speichermedium, KMS/HSM, Schlüsselrotation, lange Fuzz-Kampagne, unabhängiger Penetrationstest, Windows/macOS, Mehrhost/NFS, formal vollständige Recovery.
- Eine kompromittierte Master-Key- oder Runtime-Trust-Domain, Same-UID-/Root-Angreifer und ein feindliches Dateisystem liegen außerhalb des geprüften Modells.
- Historische V1-Quittungen enthalten keine authentifizierte Kette; Formfehler werden erkannt, gleichlange Manipulationen können und sollen in V1 **nicht** als beweisbar ausgeschlossen gelten.
- Das HMAC-Kettenprüfen bei jeder vollständigen Validierung hat wachsende O(n)-Kosten pro `verify`. Unbegrenzte Quittungshistorien sind aktuell nicht für Produktionslast geeignet.

## Quellen/Belege

Siehe `AUDIT_2026-10-24.md`, `RELEASE_GATES.json`, `EVIDENCE/benchmark_compare.csv`, `EVIDENCE/final_tests.txt`, `EVIDENCE/final_coverage.txt` und `MANIFEST_SHA256.txt`.
