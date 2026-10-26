# === / Equal3 v0.7.14 – isolated writer boundary (RESEARCH ONLY / NO-GO)

## Added modules

- `writer_service_v0714.py`: POSIX/Linux Unix-domain socket writer reference, with `SO_PEERCRED` UID checking, bounded frame sizes, private StateStore key, `DELETE/EXTRA` mode only, serialized writes, bounded connection slots, persistent request IDs and authenticated replay checking.
- `test_writer_service_v0714.py`: 21 new tests including actual *Linux root-to-separate-UID* test. Simulated patched-runtime policy in positive test fixture is **NOT** a genuine signed approval.
- `bench_writer_v0714.py`: synthetic in-process ABBA microbenchmark, direct StateStore vs protected WriterCore dispatch. Does not measure IPC, production concurrency, or patched SQLite.

## Important fail-closed boundary

The public `serve` CLI does **not** start on this research release:
(1) it requires a signed approved patched SQLite runtime; current runtime is 3.46.1;
(2) it also requires an independent monotonic anchor and commit attestation, not implemented as a production coordinator; `_research_unanchored=True` is test fixture only and is not exposed through CLI.

This is intentional. Do not call this a production writer isolation service. Clients could still bypass the facade in a deployment where they can directly access StateStore key and DB; a deployment must enforce separate OS UIDs, ACLs, mount namespaces/privileges and sole-writer topology.

## Test evidence

21/21 new tests PASS. Existing 265/265 tests PASS in four *independent subprocess batches* (91+57+94+23). A single-process monolithic run did not finish before the imposed timeout; it is **not** counted as a PASS. Test logs are in `EVIDENCE_V0714`.

## Benchmarks

Only in-process dispatch versus direct proposal+apply; median-of-two round medians, ABBA order, 24 measured iterations per round after 5 warmups. A service IPC / auth / cryptographic policy / root-key storage benchmark has **not** been run; microbenchmarks must not be extrapolated.

## Sources and constraints

- SQLite WAL race: https://www.sqlite.org/wal.html
- SQLite `synchronous=EXTRA`: https://www.sqlite.org/pragma.html#pragma_synchronous
- Linux SO_PEERCRED: https://man7.org/linux/man-pages/man7/unix.7.html
- OWASP key management: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

No GitHub pushes, merges, deployments or modifications to existing repo. No production credentials included. SHA-256 manifests prove package consistency only; no independent signer.
