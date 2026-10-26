# Equal3 v0.7.18 Research – Root-authorized attester rotation

**NO-GO / nicht für Produktionsdaten.** Forschungs-Erweiterung des überprüften v0.7.17-Pakets.

## Neue Module

- `trust_rotation_v0718.py`: `RootControlledCASAnchor`, `sign_rotation` (nur Offline-Test/Hilfsfunktion), Root-Überprüfung, atomischer Update-Pfad, Trust-Epoch-Floor.
- `rotate_attester_v0718.py`: Offline-Anwenderkommando, akzeptiert bereits extern unterzeichnetes Zertifikat; kein Erzeugen der Signatur durch den Anker.
- `anchor_wire.py`: Standard-Serve verlangt `--root-public-key-file` und `--trusted-min-epoch` bei attestiertem Betrieb; `--allow-unrooted-research-only` ist bewusst unsicher.
- `test_root_rotation_v0718.py`: gezielte Falsifikation und Funktionstests.

## Reproduzieren

```bash
python -W error::ResourceWarning -m unittest -q test_root_rotation_v0718
python run_v0718_suites.py
python bench_root_v0718.py
sha256sum -c MANIFEST_SHA256.txt
```

**Wichtige externe Voraussetzung:** Das externe Vertrauenssystem muss den Root-Fingerprint und die Mindest-Epoche unabhängig liefern. Eine lokale Datei mit Floor 0 ist kein Sicherheitsgewinn gegen Joint Rollback. Für produktive Root-Rotation wäre ein Threshold-/Cross-Sign-Verfahren zu entwickeln (vgl. TUF).
