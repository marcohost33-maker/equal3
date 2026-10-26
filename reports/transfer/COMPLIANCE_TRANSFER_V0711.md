# Equal3 v0.7.11 — 007acc2 compliance/assurance transfer (proposed, not written into central sheet)

- EQ-0711-01: Runtime provenance; externally issued Ed25519 approval, exact effective library, 30d max validity. Implemented candidate gate, independently issued authorization **NOT** available, state OPEN.
- EQ-0711-02: SQLite patched WAL runtime; old Python SQLite 3.46.1 => FAIL/HOLD. Official 3.54.1 ZIP pinned but unavailable for local build; OPEN.
- EQ-0711-03: Cryptographic root-of-trust administration; pinned public key held separately, revocation path and time trust; OPEN.
- EQ-0711-04: Unencrypted DB/WAL/SHM/temp/backups, no key lifecycle; OPEN.
- EQ-0711-05: Shared rollback between authority and store remains unprevented without independent monotonic trust; OPEN.
- EQ-0711-06: Privacy assessment (Swiss DSG) and retention depend on real data use, none used in current synthetic test; REVIEW_REQUIRED.
- EQ-0711-07: SHA-256/ SHA3-256 checksums != digital signatures, signed runtime policy does NOT imply release; HOLD.

No sensitive real-user datasets used; no central governance/compliance spreadsheet modified.
