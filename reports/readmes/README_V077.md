# === / Equal3 v0.7.7 – authority-state MAC + SQLite runtime gate

24.10.2026 · RESEARCH ONLY · RELEASE NO-GO

## Reproduzierbarkeit

In einem temporären, privaten Verzeichnis auf Linux/Python >= 3.13:

```sh
python -m unittest discover -p 'test_*.py' -v
python -m unittest -v test_anchor_v077 test_anchor_wire
python bench_seal_v077.py
sha256sum -c MANIFEST_V077.sha256
```

Präzise Quelle sind die lokalen Artefakte in `EVIDENCE_V077`. Keine echten Daten/Produktionsschlüssel einsetzen.

## Änderungen gegenüber v0.7.6

- `anchor_wire.py`: authentifizierte Authority-Tupel (Store-ID, Version, Digest, Pending)
  mittels HMAC-SHA256 mit neuem **eigenen** 32-Byte-Siegel-Schlüssel.
- Jede Statusabfrage prüft das Siegel; Prepare/Finalize/Abort aktualisieren es atomar.
- Bestehende v0.7.6-Authority-Dateien besitzen kein Siegel und sind nicht automatisch
  migrierbar. Fail-closed, bis externe Attestation plus überprüfte Recovery durchgeführt ist.
- SQLite-WAL-Reset-Race-Preflight gemäß `https://sqlite.org/wal.html`.
- CLI benötigt `--seal-key-file`; Schlüssel müssen in privaten 0600-Dateien liegen.
  **Das ist nicht hinreichend als OS-basierte Isolation.**
- Ein `--allow-unsafe-sqlite-research-only`-Flag ermöglicht die bestehenden
  **synthetischen** Tests mit SQLite 3.46.1, NICHT produktiven Betrieb.

## Grenzen

Ein MAC schützt nicht gegen gemeinsames Rollback von Anker, Datenbank und gültigem
historischen MAC. Die Schlüssel sind im Prototyp nicht in einem HSM/KMS. `consumed`
und `review_log` werden nicht durch dieses neue MAC verkettet. Die Windows-/macOS-
Ports, manuelle Altbestands-Migration, unabhängiger Writer/Attester, echte FS-Crash-
Simulation, Verschlüsselung, Pen-Test und unabhängige Codefreigabe fehlen.

Vor einem neuen Betrieb: `AUDIT_V077.md` und `RELEASE_GATES_V077.json` lesen.
Alte Manifestdateien der Vorversionen wurden nicht in das neue Artefakt kopiert,
weil sie die geänderte Version NICHT authentifizieren und sonst fehlschlagen würden.
