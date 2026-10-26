# PR/NR-Technologietransfer 0.7.17

**NR-EQ17-01**: Ed25519-Observation kann beim Neustart von einem neu übergebenen Public-Key akzeptiert werden, falls keine persistente Policy-Bindung existiert.
**PR-EQ17-01**: Trust-Policy `store_id/deployment_id/key_fingerprint` mit domain-separiertem HMAC und obligatorischem Recheck beim Authority Load.
**NR-EQ17-02**: Nachträglich eingefügte zweite Trust-Binding-Zeile nicht nur anhand `WHERE id=1` ignorieren; DDL-Manipulation testweise simulieren.
**Best Practice:** Negativ-Test auf Original v0.7.16 vor Implementierung, positive Testkontrolle, Wiederanlauf, neue/alte Authority-Schemata, kein Auto-Migrate, Dateihash-basierter ABBA-Vergleich, explizite Liefer-Gates. Kein Merge/Push.
