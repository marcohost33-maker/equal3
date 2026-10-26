# CodeFactory knowledge transfer — Equal3 v0.7.5

Reusable **research** components: receipt-inclusive snapshot audit, `Intent` plus `Position` contracts, precommit prepare CAS, strict state classification, fail-closed recovery, review authorization scoped to operation + request + store + version + digest, negative-first tests, reproducible complete ZIP. **Do not** integrate `MemoryCASAnchor` as a real security control, expose `test_only_review_token`, distribute store secrets to clients, or claim raw writer isolation.

Work pattern: spec/threat boundary → mutation/falsification → implementation → full inherited regression → controlled benchmark → fail-closed release gate → manifest/replay. To port to CodeFactory: pin exact source hash, standalone negative tests for missing/stale/forged evidence, validate independent service ownership, compare the target repository's interface, and require owner approval before any merge or write.

Measured regression and linearly growing history verification remain open optimization areas. Both positive *and* negative controls must be part of future acceptance.
