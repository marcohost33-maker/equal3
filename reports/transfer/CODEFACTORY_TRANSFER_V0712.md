# Equal3 v0.7.12 — reusable CodeFactory quality patterns

1. **Negative-first test of authenticated data:** modify both data and unkeyed digest, and test every consumer API. A successful SQLite `integrity_check` or SHA-256 comparison is not authenticity.
2. **Genesis is a real state:** chains must compare version-zero material to the genesis commitment; treating empty history as implicitly trusted creates a bypass.
3. **Legacy statuses are not green:** `LEGACY_UNSEALED` and missing source signing authority must not be turned into `MATCH`/`GO` by higher-level wrappers.
4. **Benchmark code identity is a measured variable:** execute variants in separate fixed-CWD interpreters, assert absolute imported module path, store raw CSV, and reject mistaken identical-code comparisons.
5. **Retest old contract assertions:** stronger invalid-input validation may legitimately change a prior `DIVERGENCE_HOLD` to `INVALID_DB_HOLD`; explain such changes instead of skipping tests.
6. **Release is a conjunction, not a score:** all P0 infrastructure gates independent, even if 250/250 unit tests pass. Source-manifest hashes do not substitute signature verification.

No changes to separate CodeFactory repositories were made.
