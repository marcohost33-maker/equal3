# CodeFactory Transfer Candidate – Commit Identity Gate
**ID** CF-EQ3-REQFORK-001; **status** RESEARCH TESTED, NOT DEPLOYED ELSEWHERE.
Invariant: `(version, state_digest)` is insufficient to prove *which operation* committed; validate `(store_id, version, state_digest, request_id)` against an authenticated, coherent receipt of the same version and an externally signed floor.
Reusable tests: two valid signed branches share genesis, version, and identical state bytes; use distinct request IDs; ensure mismatch is HOLD. Include zero-genesis and legitimate matching-ID controls, external floor before/after and authority recheck. Provenance: source diff + negative-first old failure + 29 passing focused tests.
Trust boundary: dependent keys and joint rollback remain P0; require independent anchors for promotion. Candidate applications: Digi, Insandbox, CodeFactory/other state machine orchestrators.
