# Equal3 v0.7.20 – CodeFactory Wissenstransfer

Pattern: fail-closed postfinal witness CAS, domain-separierte signierte Checkpoints, monotone `(version,digest,request_id)` State-Machine, Server-Side HMAC-Seal, frisch signierte RPC Challenge, vor/nach erfolgreicher API-Antwort verifizierter Zustand, strikte Schema- und Datei-Modusprüfung, Negativtest jeder Trust-Grenze.

Reproduzierbarkeit: `python -W error::ResourceWarning -m unittest -q test_external_commit_witness_v0720`; `python run_v0720_suites.py`; `python benchmark_v0720.py`.

Nicht als Vorbild für Production Enforcement kopieren: Forschungs-Klassen bleiben importierbar, lokale Unix-Sockets schützen keinen Administrator und halten den externen Zeugen nicht physisch unabhängig. Resolver/Recovery nicht automatisch ausführen; HOLD bis zur auditierbaren Klärung.
