"""Reproducible, synthetic *local research* measurements. No release claim.

Measures time of the operation with prebuilt proposal (i.e., excludes encoding)
and includes both phases for simulated protocol. Comparisons are diagnostic:
MemoryCASAnchor is volatile/in-process and has no remote I/O or credentials.
"""
from __future__ import annotations
import csv, hashlib, json, platform, secrets, sqlite3, statistics, tempfile, time
from pathlib import Path
from state_store import StateStore, prepare_update
from anchor_protocol import MemoryCASAnchor, CoordinatedStore, position_for_genesis
from guarded_store import GuardedStore
import witness


def pct(xs, q):
    xs=sorted(xs)
    ix=(len(xs)-1)*q
    low=int(ix)
    return xs[low]+(xs[min(low+1,len(xs)-1)]-xs[low])*(ix-low)


def generate(seed, size):
    out=b''; i=0
    while len(out)<size:
        out+=hashlib.sha256(f'{seed}:{i}'.encode()).digest();i+=1
    return out[:size]


def collect_method(mode,size,iteration,steps=24):
    with tempfile.TemporaryDirectory() as d:
        root=Path(d); key=hashlib.sha256(f'master:{iteration}:{size}:{mode}'.encode()).digest()
        store=StateStore.create(root/'db.sqlite',key=key,initial=generate('genesis',size))
        if mode=='guarded':
            path=root/'trusted'/'witness';path.parent.mkdir(mode=0o700)
            wk=hashlib.sha256(f'witness:{iteration}'.encode()).digest()
            witness.initialize(store,path,wk);client=GuardedStore(store,path,wk)
        elif mode=='prepared':
            a=MemoryCASAnchor(position_for_genesis(store),reviewer_key=hashlib.sha256(f'reviewer:{iteration}'.encode()).digest())
            client=CoordinatedStore(store,a)
        times=[]
        for i in range(steps):
            packet,_=prepare_update(store,generate(f'{i}:{iteration}',size),strategy='fast')
            t0=time.perf_counter_ns()
            if mode=='raw':store.apply(packet)
            elif mode=='guarded':client.apply(packet)
            else:
                client.apply(packet)
                p=a.status().pending
                client.adjudicate('FINALIZE_COMMIT',a.test_only_review_token(p,'FINALIZE_COMMIT'))
            times.append((time.perf_counter_ns()-t0)/1e6)
        assert store.verify()['version']==steps
        return times


def verify_growth():
    with tempfile.TemporaryDirectory() as d:
        s=StateStore.create(Path(d)/'log.sqlite',key=b'K'*32,initial=b'A'*1024)
        rows=[]
        for seq in range(201):
            if seq in (0,25,50,100,200):
                elapsed=[]
                for _ in range(10):
                    a=time.perf_counter_ns()
                    s.verify()
                    elapsed.append((time.perf_counter_ns()-a)/1e6)
                rows.append({'version':seq,'verify_p50_ms':round(statistics.median(elapsed),4),'verify_p95_ms':round(pct(elapsed,.95),4),'measurements':len(elapsed)})
            if seq<200:
                proposal,_=prepare_update(s,generate(f'growth:{seq}',1024),strategy='fast')
                s.apply(proposal)
        return rows


def main():
    out=Path('EVIDENCE');out.mkdir(exist_ok=True)
    cases=[]
    for size in (1024,65536):
        for run in (1,2):
            # Interleaving method order partly offsets temporal noise.
            methods=('raw','guarded','prepared') if run==1 else ('prepared','guarded','raw')
            for mode in methods:
                samples=collect_method(mode,size,run)
                cases.append({'payload_bytes':size,'run':run,'method':mode,'n':len(samples),
                              'p50_ms':round(statistics.median(samples),4),
                              'p95_ms':round(pct(samples,.95),4),
                              'min_ms':round(min(samples),4), 'max_ms':round(max(samples),4)})
    growth=verify_growth()
    with (out/'benchmark_v075.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=cases[0].keys());w.writeheader();w.writerows(cases)
    with (out/'verify_growth_v075.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=growth[0].keys());w.writeheader();w.writerows(growth)
    results={'platform':platform.platform(),'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,
             'benchmark_contract':'synthetic single-process SQLite WAL FULL, 24 updates each per case (no dedicated warmup), proposal prepared outside timing; simulator per-write manual reviewer token; NOT a real independent anchor',
             'methods':cases,'verify_growth':growth}
    (out/'benchmark_v075.json').write_text(json.dumps(results,indent=2)+'\n')
    for row in cases:print(row)
    print('GROWTH',growth)

if __name__=='__main__':main()
