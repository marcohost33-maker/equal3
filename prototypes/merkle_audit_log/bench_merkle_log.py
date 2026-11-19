"""Cost of the RFC 9162 log operations at 1k/10k/100k events (compare docs/ADR-002).

Times append (incl. root update), root(), and verification of an inclusion proof
and of a consistency proof from the previous checkpoint. Proof generation in this
prototype recomputes subtree hashes (O(n)) and is reported separately; a
production log would store interior nodes. Percentiles: nearest rank.
Usage: python prototypes/merkle_audit_log/bench_merkle_log.py [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import merkle_log as ml  # noqa: E402

SIZES = (1000, 10000, 100000)
REPEATS = 200


def pct(samples, p):
    s = sorted(samples)
    return s[max(1, math.ceil(p / 100 * len(s))) - 1]


def stats(samples):
    us = [x * 1e6 for x in samples]
    return {'n': len(us), 'p50_us': round(pct(us, 50), 2), 'p95_us': round(pct(us, 95), 2),
            'p99_us': round(pct(us, 99), 2)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--json')
    args = ap.parse_args(argv)
    log, rows, previous = ml.MerkleLog(), [], (0, None)
    for size in SIZES:
        appends = []
        while len(log) < size:
            t = time.perf_counter()
            log.append(b'event-%d' % len(log))
            log.root()
            appends.append(time.perf_counter() - t)
        root = log.root()
        t = time.perf_counter()
        index = size // 3
        path = log.inclusion_proof(index)
        first = previous[0] or size // 2
        first_root = previous[1] or ml.mth(log.leaves[:first])
        proof = log.consistency_proof(first)
        generation_s = time.perf_counter() - t
        inc, con = [], []
        for _ in range(REPEATS):
            t = time.perf_counter()
            ok_i = ml.verify_inclusion(index, size, log.leaves[index], path, root)
            inc.append(time.perf_counter() - t)
            t = time.perf_counter()
            ok_c = ml.verify_consistency(first, size, first_root, root, proof)
            con.append(time.perf_counter() - t)
        if not (ok_i and ok_c):
            raise SystemExit('proof verification failed at size %d' % size)
        row = {'events': size, 'append_with_root': stats(appends[-1000:]),
               'verify_inclusion': stats(inc), 'inclusion_proof_hashes': len(path),
               'verify_consistency': stats(con), 'consistency_from': first,
               'consistency_proof_hashes': len(proof), 'proof_generation_s_prototype': round(generation_s, 4)}
        rows.append(row)
        previous = (size, root)
        print('events=%-7d append+root p50 %6.1f us | verify inclusion p50 %6.1f us (%d hashes) | '
              'verify consistency %d->%d p50 %6.1f us (%d hashes)' % (
                  size, row['append_with_root']['p50_us'], row['verify_inclusion']['p50_us'], len(path),
                  first, size, row['verify_consistency']['p50_us'], len(proof)), flush=True)
    result = {'tool': 'prototypes/merkle_audit_log/bench_merkle_log.py', 'python': sys.version.split()[0],
              'percentile_method': 'nearest rank', 'points': rows}
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
