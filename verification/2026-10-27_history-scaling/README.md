# History scaling of the O(n) checks — 2026-10-27 (roadmap P1, finding NR-07)

**Result: both history checks grow linearly, and both become second-scale at 100 000 entries.**
- An anchor operation recomputes the audit digest. At its cap of 100 000 ledger rows this takes
  904 ms P50 / 1 097 ms P99, and one more row turns the anchor into a permanent HOLD.
- An authenticated `StateStore.read()` takes 1.75 s P50 / 2.38 s P99 at 100 000 commits.
- Writes stay constant (about 4 ms per commit).

The RFC 9162 prototype verifies a consistency proof from 10 000 to 100 000 events in about 21 µs
(14 hashes). Design proposal: [docs/ADR-002](../../docs/ADR-002_checkpointed-audit-log.md).
The release decision stays **NO-GO**.

This folder is not part of the import. Produced in the Claude Code maintenance channel.

**Exploratory measurement.** One machine, N = 30 to 100 per point. Treat P99 as an indication: at
N = 30 it is the maximum (nearest rank), not a tail estimate. The numbers show growth, not a
service-level guarantee. A tail claim would need a few hundred samples per point and repeated runs.

## Method

- Tool: [`tools/bench_history_scaling.py`](../../tools/bench_history_scaling.py) on the unmodified
  research modules; prototype: [`prototypes/merkle_audit_log/bench_merkle_log.py`](../../prototypes/merkle_audit_log/bench_merkle_log.py).
- **StateStore:** journal mode DELETE (with `synchronous=EXTRA`, the hardened mode since v0.7.13).
  - The history is grown with real commits through `StateStore.apply()`. Proposals are built with
    the public `make_proposal()` / `equal3.encode_bytes()`, because `prepare_update()` itself calls
    `read()` and would make the setup O(n²).
  - At 1k/10k/100k commits, `read()` runs 100/100/30 times; every read checks that it returns the
    expected version and value.
- **Anchor:** `PersistentCASAnchor._audit_digest()` runs 30 times on a ledger with well-formed rows in
  the per-commit ratio of 2 consumed nonces to 1 review row. Only the digest function is timed;
  the ledger is not sealed.
- **Cap:** the digest is also run on `MAX_AUDIT_ROWS + 1` rows.
- **Percentiles:** nearest rank. With fewer than 100 samples, P99 equals the maximum (the 100k read
  row: N = 30).
- **Environment:** Linux x86_64, 4 CPUs, Python 3.13.17, SQLite 3.45.1, ext4-class file system,
  commit `2ff57dd`. Total run time 511 s.

## Results

[bench_delete.json](bench_delete.json)

| Path | Entries | P50 | P95 | P99 | N |
|---|---:|---:|---:|---:|---:|
| anchor audit digest (every anchor operation) | 1 000 rows | 8.4 ms | 11.7 ms | 11.8 ms | 30 |
| | 10 000 rows | 74.5 ms | 107.0 ms | 107.4 ms | 30 |
| | 100 000 rows (cap) | 903.9 ms | 1 058.7 ms | 1 097.4 ms | 30 |
| | 100 001 rows | **HOLD** "audit ledger capacity exceeded; operator review required" | | | |
| `StateStore.read()` (every authenticated read) | 1 000 commits | 14.2 ms | 23.8 ms | 24.0 ms | 100 |
| | 10 000 commits | 142.2 ms | 187.9 ms | 204.2 ms | 100 |
| | 100 000 commits | 1 746.1 ms | 2 176.6 ms | 2 379.4 ms | 30 |
| `StateStore.apply()` (last 1 000 commits of each segment) | 1 000 / 10 000 / 100 000 | 3.7 / 3.2 / 4.2 ms | | 7.7 / 6.3 / 9.2 ms | 1 000 |

- Least-squares slopes of the P50 values: 9.1 µs per anchor ledger row and 17.6 µs per StateStore
  receipt. Both are linear, as the code comments say ("deliberately O(n)").
- The anchor cap is reached after about **33 333 commits** (3 ledger rows each).
- The store file grows to 18.1 MB at 100 000 commits.

### RFC 9162 prototype on the same sizes

[bench_merkle_prototype.json](bench_merkle_prototype.json), N = 200 per verification:

| Events | append + root P50 | verify inclusion P50 (hashes) | verify consistency P50 (hashes) |
|---:|---:|---:|---:|
| 1 000 | 6.9 µs | 12.6 µs (10) | 15.7 µs (9), 500 → 1 000 |
| 10 000 | 8.9 µs | 17.5 µs (14) | 19.6 µs (12), 1 000 → 10 000 |
| 100 000 | 9.7 µs | 20.9 µs (17) | 20.9 µs (14), 10 000 → 100 000 |

Proof generation in the prototype recomputes subtree hashes and is not timed as a hot path (see
ADR-002, consequences).

## What this shows and what it does not

- It shows that NR-07 is real and quantifies it. The anchor cap is an availability limit, not only
  a slowdown: an attacker who can trigger commits, or ordinary long-running use, drives the anchor
  into a HOLD that needs an operator.
- It does not measure the full RPC path, concurrent clients, or an fsync-heavy storage medium.
  Timings vary with CPU and disk.
- The prototype is not wired into the anchor. Moving the full check out of the hot path is a
  security trade-off that ADR-002 states explicitly. Implementing it needs its own research round.

## Kurzfassung (Deutsch)

Beide O(n)-Prüfungen wachsen linear. Bei 100 000 Einträgen kostet:
- jede Anker-Operation rund 0,9 s;
- jeder authentifizierte Read rund 1,7 s (P99 2,4 s).

Ab 100 001 Ledger-Zeilen, also nach etwa 33 333 Commits, geht der Anker dauerhaft in HOLD.
Schreiben bleibt konstant bei etwa 4 ms.

Ein Merkle-Log nach RFC 9162 prüft dieselbe Historie mit 14–17 Hashes in rund 21 µs. Der
Umbauvorschlag mit dem ausdrücklich benannten Sicherheits-Trade-off steht in ADR-002. Freigabe
bleibt NO-GO.
