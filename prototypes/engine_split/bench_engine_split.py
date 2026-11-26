#!/usr/bin/env python3
"""Exploratory cost measurement: one anchored SET + FINALIZE, research v0.7.15 vs the candidate.

Both verify the full keyed receipt history on every authenticated read (O(N), roadmap P1); the
question here is how many such verifications one SET costs in each, and what that means in time
at a given history length. Counts come from wrapping _verified_snapshot; times are wall clock,
N = --repeat samples per point, median reported. Exploratory, one host, not a benchmark claim.
The history is built with the research store first; both test-double anchors only accept a
genesis position, so the benchmark sets the double's committed position to that head directly
(bench-only; it is a volatile in-process double either way).

Usage (repository root): python prototypes/engine_split/bench_engine_split.py [--history 0 200 1000]
                                                                              [--repeat 7] [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent.parent / 'research'), str(HERE)]

import anchor_protocol as r_anchor  # noqa: E402
import anchored_writer_v0715 as r_writer  # noqa: E402
import state_store as r_store  # noqa: E402
import eq3_anchor_lab as lab  # noqa: E402
import eq3_anchored_writer as c_writer  # noqa: E402
import eq3_coordinator as c_coord  # noqa: E402
import eq3_engine as engine_mod  # noqa: E402
import eq3_wire as wire  # noqa: E402

KEY = b'K' * 32
REVIEWER = b'R' * 32


def head_position(cls, info):
    return cls(info['store_id'], info['version'], info['digest_sha256'])


def genesis_position(cls, path):
    import sqlite3
    with sqlite3.connect('file:%s?mode=ro' % path, uri=True) as db:
        sid, gen = db.execute('SELECT store_id, genesis_digest FROM meta').fetchone()
    return cls(sid.hex(), 0, gen.hex())


def build(path, impl):
    if impl == 'research':
        store = r_store.StateStore(path, key=KEY, journal_mode='DELETE')
        anchor = r_anchor.MemoryCASAnchor(genesis_position(r_anchor.Position, path), reviewer_key=REVIEWER)
        anchor._committed = head_position(r_anchor.Position, store.verify())
        return r_writer.AnchoredWriterCore(store, anchor), anchor, r_store.StateStore, '_verified_snapshot'
    engine = engine_mod.StateEngine(path, key=KEY)
    anchor = lab.MemoryCASAnchor(genesis_position(lab.Position, path), reviewer_key=REVIEWER)
    anchor._committed = head_position(lab.Position, engine.verify())
    engine, cap = engine_mod.bind_writer(path, key=KEY, anchor=anchor)
    return c_writer.AnchoredWriterCore(engine, cap, anchor), anchor, engine_mod.StateEngine, '_verified_snapshot'


def cycle(core, anchor, n):
    rid = n.to_bytes(16, 'big')
    reply = core.dispatch(wire.SET, rid, b'state %d ' % n * 4)
    assert reply['error'] == 'EXTERNAL_REVIEW_REQUIRED', reply
    pending = anchor.status().pending
    code = core._coordinator.adjudicate('FINALIZE_COMMIT', anchor.test_only_review_token(pending, 'FINALIZE_COMMIT')).code
    assert code == 'MATCH', code


def measure(history, repeat, tmp):
    genesis = tmp / ('g%d.sqlite' % history)
    r_store.StateStore.create(genesis, key=KEY, initial=b'genesis', journal_mode='DELETE')
    store = r_store.StateStore(genesis, key=KEY, journal_mode='DELETE')
    for i in range(history):   # history built with the research store (same format)
        proposal, _ = r_store.prepare_update(store, b'h%d' % i, request_id=(10**9 + i).to_bytes(16, 'big'))
        store.apply(proposal)
    result = {}
    for impl in ('research', 'candidate'):
        times, verifications = [], []
        for r in range(repeat):
            path = tmp / ('%s-%d-%d.sqlite' % (impl, history, r))
            shutil.copyfile(genesis, path)
            core, anchor, cls, name = build(path, impl)
            original = getattr(cls, name)
            calls = [0]

            def counted(self, *a, **kw):
                calls[0] += 1
                return original(self, *a, **kw)
            setattr(cls, name, counted)
            try:
                start = time.perf_counter()
                cycle(core, anchor, r + 1)
                times.append(time.perf_counter() - start)
            finally:
                setattr(cls, name, original)
            verifications.append(calls[0])
        result[impl] = {'median_ms': round(statistics.median(times) * 1000, 2),
                        'full_history_verifications': sorted(set(verifications))}
    result['ratio'] = round(result['candidate']['median_ms'] / result['research']['median_ms'], 2)
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--history', type=int, nargs='+', default=[0, 200, 1000])
    p.add_argument('--repeat', type=int, default=7)
    p.add_argument('--json', type=Path)
    a = p.parse_args(argv)
    import platform, sqlite3
    out = {'python': platform.python_version(), 'sqlite': sqlite3.sqlite_version,
           'repeat': a.repeat, 'points': {}}
    with tempfile.TemporaryDirectory(prefix='eq3bench-') as t:
        for h in a.history:
            out['points'][str(h)] = measure(h, a.repeat, Path(t))
            print(h, json.dumps(out['points'][str(h)]))
    if a.json:
        a.json.write_text(json.dumps(out, indent=2) + '\n')


if __name__ == '__main__':
    main()
