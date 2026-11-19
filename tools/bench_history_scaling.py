#!/usr/bin/env python3
"""Measure how the O(n) history checks of Equal3 scale (roadmap P1, finding NR-07).

Two code paths of the unmodified research modules are timed:

1. StateStore.read() — verifies the whole HMAC receipt chain and runs
   PRAGMA integrity_check on every authenticated read. The history is grown
   with real commits through StateStore.apply(); proposals are built with the
   public make_proposal()/equal3.encode_bytes() so that growing the history
   stays O(1) per commit (prepare_update() itself calls read()).
2. PersistentCASAnchor._audit_digest() — recomputed over the whole anchor
   audit ledger (consumed nonces + review log) on every anchor operation and
   capped at MAX_AUDIT_ROWS. The ledger is filled with well-formed rows in the
   ratio of one commit (2 consumed nonces + 1 review row), because only the
   digest function is timed; the cap itself is checked one row above it.

Percentiles use the nearest-rank method (sorted sample at ceil(p/100 * N)); with
fewer than 100 samples P99 is the maximum, and the JSON says how many samples
each percentile rests on. Timings are wall clock on the machine that ran this;
they show growth, not a service-level guarantee.

Usage: python tools/bench_history_scaling.py [--sizes 1000,10000,100000]
       [--journal DELETE|WAL] [--json OUT]
POSIX only, stdlib plus the research modules (and their dependency).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import secrets
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

RESEARCH = Path(__file__).resolve().parent.parent / 'research'
PERCENTILES = (50, 95, 99)


def percentile(samples, p: float) -> float:
    """Nearest-rank percentile of a non-empty sample."""
    if not samples:
        raise ValueError('empty sample')
    ordered = sorted(samples)
    return ordered[max(1, math.ceil(p / 100 * len(ordered))) - 1]


def summarize(samples_s) -> dict:
    ms = [s * 1e3 for s in samples_s]
    out = {'n': len(ms), 'mean_ms': round(statistics.fmean(ms), 4), 'max_ms': round(max(ms), 4)}
    for p in PERCENTILES:
        out['p%d_ms' % p] = round(percentile(ms, p), 4)
    return out


def slope_per_row(points) -> float | None:
    """Least-squares slope of median milliseconds over rows, in microseconds per row."""
    if len(points) < 2:
        return None
    xs, ys = [x for x, _ in points], [y for _, y in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    denom = sum((x - mx) ** 2 for x in xs)
    return None if denom == 0 else round(sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom * 1e3, 4)


def reads_for(size: int) -> int:
    return 100 if size <= 10000 else 30


def bench_store(sizes, journal: str, workdir: Path) -> dict:
    import equal3
    from state_store import StateStore, make_proposal
    key = secrets.token_bytes(32)
    store = StateStore.create(workdir / 'state.sqlite', key=key, initial=b'genesis', journal_mode=journal)
    sid, prev, version = store.store_id, b'genesis', 0
    rows, read_points = [], []
    for size in sizes:
        apply_samples = []
        while version < size:
            target = b'v%010d' % version
            proposal = make_proposal(sid, version, secrets.token_bytes(16),
                                     equal3.encode_bytes(prev, target, key=key), key=key)
            t = time.perf_counter()
            store.apply(proposal)
            apply_samples.append(time.perf_counter() - t)
            prev, version = target, version + 1
        read_samples = []
        for _ in range(reads_for(size)):
            t = time.perf_counter()
            snap = store.read()
            read_samples.append(time.perf_counter() - t)
        if snap.version != size or snap.value != prev:
            raise RuntimeError('read returned version %d, expected %d' % (snap.version, size))
        row = {'history_receipts': size, 'read': summarize(read_samples),
               'apply_last_segment': summarize(apply_samples[-1000:]),
               'db_bytes': (workdir / 'state.sqlite').stat().st_size}
        rows.append(row)
        read_points.append((size, row['read']['p50_ms']))
        print('store  n=%-7d read p50 %9.2f ms  p95 %9.2f ms  p99 %9.2f ms  (N=%d)   apply p50 %.2f ms' % (
            size, row['read']['p50_ms'], row['read']['p95_ms'], row['read']['p99_ms'], row['read']['n'],
            row['apply_last_segment']['p50_ms']), flush=True)
    return {'journal_mode': journal, 'points': rows, 'read_p50_slope_us_per_receipt': slope_per_row(read_points)}


def _fill_anchor_ledger(db, rows: int) -> None:
    """Well-formed ledger rows in the per-commit ratio 2 consumed nonces : 1 review row."""
    consumed, review = [], []
    while len(consumed) + len(review) < rows:
        consumed.append((secrets.token_hex(16), 'prepare'))
        if len(consumed) + len(review) < rows:
            consumed.append((secrets.token_hex(16), 'adjudicate'))
        if len(consumed) + len(review) < rows:
            review.append((len(review) + 1, secrets.token_hex(16), 'FINALIZE_COMMIT', len(review) + 1))
    db.executemany('INSERT INTO consumed VALUES (?,?)', consumed)
    db.executemany('INSERT INTO review_log VALUES (?,?,?,?)', review)
    db.commit()


def bench_anchor(sizes, workdir: Path, repeats: int) -> dict:
    import anchor_wire
    from anchor_wire import PersistentCASAnchor, AnchorHold
    cap = anchor_wire.MAX_AUDIT_ROWS
    rows, points = [], []
    for size in [s for s in sizes if s <= cap]:
        path = workdir / ('ledger_%d.sqlite' % size)
        with closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE consumed(nonce TEXT PRIMARY KEY, operation TEXT NOT NULL)')
            db.execute('CREATE TABLE review_log(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL, '
                       'decision TEXT NOT NULL, version INTEGER NOT NULL)')
            _fill_anchor_ledger(db, size)
            samples = []
            for _ in range(repeats):
                t = time.perf_counter()
                PersistentCASAnchor._audit_digest(db)
                samples.append(time.perf_counter() - t)
        row = {'ledger_rows': size, 'commits_equivalent': size // 3, 'audit_digest': summarize(samples)}
        rows.append(row)
        points.append((size, row['audit_digest']['p50_ms']))
        print('anchor rows=%-7d audit digest p50 %8.2f ms  p95 %8.2f ms  p99 %8.2f ms  (N=%d)' % (
            size, row['audit_digest']['p50_ms'], row['audit_digest']['p95_ms'], row['audit_digest']['p99_ms'],
            repeats), flush=True)
    # One row above the cap: the anchor must refuse (an availability limit, not a slowdown).
    with closing(sqlite3.connect(workdir / 'ledger_cap.sqlite')) as db:
        db.execute('CREATE TABLE consumed(nonce TEXT PRIMARY KEY, operation TEXT NOT NULL)')
        db.execute('CREATE TABLE review_log(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL, '
                   'decision TEXT NOT NULL, version INTEGER NOT NULL)')
        _fill_anchor_ledger(db, cap + 1)
        try:
            PersistentCASAnchor._audit_digest(db)
            cap_result = 'ACCEPTED (unexpected)'
        except AnchorHold as exc:
            cap_result = 'HOLD: %s' % exc
    print('anchor rows=%d (cap+1): %s' % (cap + 1, cap_result), flush=True)
    return {'max_audit_rows': cap, 'commits_until_cap': cap // 3, 'points': rows,
            'audit_digest_p50_slope_us_per_row': slope_per_row(points), 'cap_plus_one': cap_result}


def environment() -> dict:
    env = {'python': sys.version.split()[0], 'sqlite': sqlite3.sqlite_version, 'platform': platform.platform(),
           'cpus': os.cpu_count(), 'tmpdir': tempfile.gettempdir()}
    try:
        env['tmpdir_fs'] = subprocess.run(['stat', '-f', '-c', '%T', env['tmpdir']], capture_output=True,
                                          text=True, timeout=10).stdout.strip() or None
    except OSError:
        env['tmpdir_fs'] = None
    try:
        env['commit'] = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=10,
                                       cwd=str(Path(__file__).resolve().parent)).stdout.strip() or None
    except OSError:
        env['commit'] = None
    return env


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--sizes', default='1000,10000,100000')
    ap.add_argument('--journal', choices=('DELETE', 'WAL'), default='DELETE')
    ap.add_argument('--anchor-repeats', type=int, default=30)
    ap.add_argument('--research-dir', default=str(RESEARCH))
    ap.add_argument('--json')
    args = ap.parse_args(argv)
    sizes = sorted({int(s) for s in args.sizes.split(',')})
    if not sizes or sizes[0] < 1 or args.anchor_repeats < 1:
        ap.error('sizes and repeats must be positive')
    sys.path.insert(0, str(Path(args.research_dir).resolve()))
    started = time.time()
    with tempfile.TemporaryDirectory() as d:
        anchor = bench_anchor(sizes, Path(d), args.anchor_repeats)
        store = bench_store(sizes, args.journal, Path(d))
    result = {'tool': 'tools/bench_history_scaling.py', 'environment': environment(),
              'percentile_method': 'nearest rank; with N < 100 samples P99 equals the maximum',
              'wall_clock_s': round(time.time() - started, 1), 'anchor_audit': anchor, 'state_store': store}
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
