# Equal3 v0.7.3 — statistischer Lern- und Falsifikationsnachtrag
| Metrik | Wert | Status | Messgrenze |
|---|---:|---|---|
| Regression | 96/96 Tests | PASS | Lokales Python unittest; nicht Produktionsbeweis |
| Neue Tests | 19 | PASS | POSIX, 2 direkte Multithread-/Multiprozesskonkurrenz-Szenarien |
| Kontrollierte Prozess-Faults | 7 | PASS inherited | Keine VFS/Torn-Write/Powerloss-Emulation |
| Witness-Integrität/Checkpoints | HMAC/canonical | POSITIVE | HMAC ist keine digitale Signatur oder unabhängiger Anchor |
| Baseline Apply 1KiB Median | 1.8289 ms | MEASURED | 40 Updates, Python SQLite |
| Guard Apply 1KiB Median | 4.2522 ms | MEASURED | 40 Updates, kein Laufzeitversprechen |
| Baseline Apply 64KiB Median | 2.1007 ms | MEASURED | 40 Updates |
| Guard Apply 64KiB Median | 4.5628 ms | MEASURED | 40 Updates |
| Gemeinsamer DB+Witness-Rollback | NICHT erkannt | FALSIFIED prior | unabhängige monotone Referenz notwendig |
| Release-Status | NO-GO | GOVERNANCE | Security-Review, VFS, KMS/Trust-Anchor fehlen |
