# Equal3 v0.7.15 – Koordinatorgebundener Writer (FORSCHUNG)

Die neue `AnchoredWriterCore`-Klasse führt einen StateStore-Write nur über `CoordinatedStore` und `anchor.prepare()` aus und liefert bis zur freigegebenen Ankerfinalisierung `ok: false`.

Verwendung nur in einer **isolierten Testumgebung**. Beispiel und echte lokale Socket-Protokolltests: `test_anchored_writer_v0715.py`.

Prüfen:

```
python -W error::ResourceWarning -m unittest -q test_anchored_writer_v0715
python run_v0715_suites.py
python benchmark_v0715_writer.py
python benchmark_rpc_v0715.py
```

Die Testsignierung erfolgt ausschließlich über synthetische Schlüssel und simulierte Reviewer. `writer_service_v0714.main(serve)` ist weiterhin bewusst `NO_GO` und nicht mit einem Produktions-Anker verbindlich verkabelt. Keine produktiven Schlüssel im Bundle. Nicht als Daten- oder Zugriffsicherheit für reale Nutzer einsetzen.

Die neue Funktion ist keine Lösung gegen gemeinsame Wiederherstellung beider Datenbanken. Der negative Test `test_joint_local_rollback_still_undetectable_without_independent_anchor` ist ein Beleg dafür.
