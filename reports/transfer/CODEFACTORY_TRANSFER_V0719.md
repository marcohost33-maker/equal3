# Reusable CodeFactory engineering patterns – Equal3 v0.7.19

- Always test claim against oldest frozen baseline before patching (negative-first).
- Separate local integrity seal, remote authentication, and real independent monotonicity; never conflate successful signature verification with durable external state.
- Signed challenge-response must include a caller-generated unguessable nonce; never accept cached signed epochs for liveness.
- Enforce strict CAS authorization and exact expected predecessor; do not permit auto-bootstrap on missing DB.
- Stop serving if a required trust check cannot complete; no silent local fallback.
- Model two-system crash windows as HOLD and require audited recovery; no distributed atomicity claims.
- Include deliberately successful known-out-of-scope attacks in tests to make trust assumptions explicit.
- Benchmark extra network/crypto work separately from full commit and capacity/liveness.
