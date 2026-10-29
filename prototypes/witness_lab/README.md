# Witness lab: signed checkpoints, external witnesses and the NR-01 rollback (roadmap P0-3)

Not part of any research version and not wired into the anchor. This lab shows the mechanism that
roadmap P0-3 asks for and [docs/ADR-002](../../docs/ADR-002_checkpointed-audit-log.md) item 4
relies on. Signed checkpoints, cosigned by witnesses outside the local rollback domain, make a
**joint rollback of all local components detectable**. That is finding NR-01, which no local
mechanism of Equal3 could detect.

## What is implemented

From the C2SP editor's copies (github.com/C2SP/C2SP @ `fea9004`, fetched 2026-10-27):

| File | Spec | Content |
|---|---|---|
| `note.py` | signed-note, tlog-checkpoint, tlog-cosignature | strict note parsing (UTF-8, no control characters, canonical base64, key-name rules); key IDs; vkeys; Ed25519 log signatures (type 0x01); timestamped Ed25519 checkpoint cosignatures (type 0x04, `cosignature/v1` + `time <t>` + checkpoint text) |
| `witness.py` | tlog-witness `add-checkpoint` | 400 / 403 / 404 / 409 (`text/x.tlog.size` body) / 422 / 200; old-size check and persistence in one `BEGIN IMMEDIATE` transaction; rejected but validly signed requests kept as misbehaviour evidence |
| `http_witness.py` | tlog-witness HTTP, RFC 9112 §6 framing | `POST /add-checkpoint`, `GET /<sha256(origin)>/checkpoint`; stdlib, 127.0.0.1 only; one Content-Length of ASCII digits, no Transfer-Encoding, size limit, complete body before the witness sees it, socket timeout; one request per connection: every response sends `Connection: close` and closes |
| `lab_log.py` | — | log operator on the RFC 9162 tree of `../merkle_audit_log`; client policy: log signature **and** a quorum of witness cosignatures **and** consistency with the largest checkpoint accepted before |

## Results

`test_witness_lab.py`, 33 tests, run as root and non-root on Linux (locally and in CI run
40931419436 for the R12 tests) and on Windows (Python 3.14.4):

| Scenario | Outcome |
|---|---|
| spec example note and vkey (signed-note) | key ID `530d903a` and signature verify (known answer) |
| first checkpoint, growth with consistency proof, same-size re-cosign | 200 |
| stale old size / old > size / unknown origin / untrusted key / bad proof / > 63 proof lines | 409 `8\n` / 400 / 404 / 403 / 422 / 400; state unchanged |
| same size with another root; non-empty proof at old size 0 | 422 |
| same-size resubmission with extra signature lines, one forged under the witness's own key ID (Codex review) | 200; only the verified log signature is stored and served, so the monitoring note still verifies |
| two concurrent requests from the same old size (10 rounds) | always exactly one 200 and one 409; stored size = winner |
| **joint rollback of log, local witness DB and client state** to size 10 after the external witnesses saw 20, then a fork to 15 | local witness **cosigns the fork** (NR-01 reproduced); external witnesses answer **409** (`20`); a client that requires 2 external cosignatures cannot accept the fork; the external witness still holds 20 > 10, so the rollback is visible |
| fork extended past the witnessed size (old 20, proof from the fork) | 422, kept as evidence with a valid log signature over a conflicting root |
| one external witness rolled back as well | that witness cosigns the fork, the other refuses; quorum 1 accepts, **quorum 2 rejects** |
| client that already accepted size 20 | rejects a forked 25 and an older 10 (`RollbackDetected`) |
| witness as a separate process over HTTP | 200, 409 with `text/x.tlog.size`, monitoring GET returns log signature and witness cosignature |
| HTTP framing: Content-Length `abc`, `+5`, `5_0`, `-5`, `0x5`, full-width digit; duplicate or list value; Transfer-Encoding with / without Content-Length; missing; 0; > 64 KiB or 5000 digits; truncated body; stalled body | 400; 400; 400 / 501; 411; 400; 413; 400; 408. No rejected request reaches the witness. |
| HTTP/1.1 keep-alive enabled: error response before the body is read (wrong path, bad Content-Length, Transfer-Encoding) | exactly one response with `Connection: close` |
| HTTP/1.0 and HTTP/1.1, 16 request paths (POST 200 / 409 / 404 / 400 / 411 / 413 / 501 / 431, GET 200 / 404 with and without body, HEAD and PUT 501, client `Connection: keep-alive`), each followed by a pipelined canary POST; real witness | exactly one response, status line in the configured version, `Connection: close`, one Content-Length equal to the body bytes; the server closes before its idle timeout; the canary never reaches the witness. Positive control: the canary alone is served. Two pipelined well-formed POSTs get one answer |
| unparsable request line (`GARBAGE`, `HTTP/9.9`, `HTTP/x`) followed by the canary | CPython answers HTTP/0.9 style (no status line, no headers); the connection still ends and the canary never reaches the witness |

**Mutation checks**, each run by hand against a copy of the code. All 17 mutants are killed:
- vkey split on every `+`;
- `BEGIN DEFERRED` instead of `IMMEDIATE`;
- old size accepted when smaller;
- consistency proof skipped;
- same-size root not compared;
- note accepted without a known signature;
- client quorum ignored;
- cosignature verified without the time line;
- HTTP framing (8): `int()` instead of the digit check, no length check after reading, first of
  duplicate Content-Length used, Transfer-Encoding ignored, no timeout handling, zero length
  allowed, size limit unchecked, no socket timeout;
- error response without `Connection: close`.

**Connection close (review R12)**, run with `Vero/Tools/diskriminierung.py` against `fbd60d8`
(run `DK-20261029T174506-ecb6d06547e0`): five mutants killed by
`HttpConnectionClose.test_every_response_closes_the_connection`, the first also by the inverted
pipelining test — close only for status >= 400 (the `8c22517` state), header removed, header
`keep-alive`, header `close` but `close_connection = False` after the write, Content-Length in
characters instead of bytes. One mutant survives on CPython 3.14.4 and is equivalent there
(run `DK-20261029T174826-ef0998499f81`): removing the explicit `close_connection = True`, because
`send_header('Connection', 'close')` also sets it (the same code is in 3.13.13, read, not run). That behaviour is not in the `http.server`
documentation, so the explicit assignment stays.

The HTTP test found a real bug before release: the base64 part of a vkey can contain `+`, so the
vkey must be split at the first two `+` only.

The cross-family review R3/R5 (2026-10-27, P1) found that the HTTP front end did not frame requests
strictly: `int(Content-Length or 0)` accepted `+5` and `5_0`, crashed on non-numeric values, and a
truncated body reached the witness. The framing tests were written first and were red on the
unchanged server (8 of 9 tests, 14 failing cases); the fix is an independent implementation, not
the reviewer's patch file. The follow-up reviews R5/R9/R10 found a latent HTTP/1.1 case: an error
answered before the body was read left the body to be parsed as a second request (404, then another
response). Every error response now closes the connection (RFC 9112 section 9.3); red first again.
Review R12 asked for the same on every response: on `8c22517` HTTP/1.1 still served a pipelined
request after a 200 (POST and GET), and HTTP/1.0 sent no `Connection: close` with a 200. Now every
response closes (RFC 9112 sections 9.3 and 9.6); the new test was red first (8 failing cases).

## What this does not show

- **Independence is an operational property, not a code property.** The external witnesses here run
  in the same machine and test process (one over HTTP in a separate process). Detection works only
  if the witnesses are operated by other parties, in another administrative domain, with their own
  keys and storage, and if the client actually requires their cosignatures.
- **Freshness.** A client that is itself rolled back and does not ask a witness accepts old state.
  The quorum must be checked on every acceptance, and the cosignature timestamps should be bounded.
  Timestamp checks are not implemented here.
- **Witness compromise.** With `f` compromised or rolled-back witnesses, a quorum of `f + 1` is
  needed. The lab shows f = 1.
- **Not integrated.** The anchor does not use this yet. Integration belongs to the research round
  that implements ADR-002, with its own audit. Release stays NO-GO.

Run: `python -m unittest -v prototypes/witness_lab/test_witness_lab.py` (needs `cryptography`).
