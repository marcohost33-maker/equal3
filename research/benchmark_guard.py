"""Benchmarks: sequential single host, validated receipt/version on each update.
Not a production throughput or cross-machine comparison.
"""
import csv, json, os, pathlib, platform, secrets, statistics, tempfile, time
from state_store import StateStore,prepare_update
from guarded_store import GuardedStore
import witness

RUNS=40

def pct(x,p):
    s=sorted(x);return s[min(len(s)-1, max(0, int((len(s)-1)*p)))]

def run():
    results=[]
    for n in (1024,65536):
        for mode in ('raw_sqlite_apply','guarded_apply'):
            with tempfile.TemporaryDirectory() as td:
                d=pathlib.Path(td);key=secrets.token_bytes(32);wkey=secrets.token_bytes(32)
                initial=bytes([42])*n
                store=StateStore.create(d/'store.sqlite',key=key,initial=initial)
                guard=None
                if mode=='guarded_apply':
                    trust=d/'witness_trust';trust.mkdir(mode=0o700)
                    witness.initialize(store,trust/'witness.txt',wkey)
                    guard=GuardedStore(store,trust/'witness.txt',wkey)
                current=initial;times=[]
                for i in range(RUNS):
                    nxt=bytearray(current)
                    nxt[(i*131)%n]=(nxt[(i*131)%n]+1)%256
                    nxt=bytes(nxt)
                    prop,_=prepare_update(store,nxt,strategy='fast')
                    t=time.perf_counter_ns()
                    if guard: guard.apply(prop)
                    else: store.apply(prop)
                    times.append((time.perf_counter_ns()-t)/1e6)
                    current=nxt
                assert store.read().value==current and store.read().version==RUNS
                if guard:assert guard.assess()=='MATCH'
                results.append({'mode':mode,'state_bytes':n,'updates':RUNS,'median_ms':round(statistics.median(times),4),
                                'p95_ms':round(pct(times,.95),4),'min_ms':round(min(times),4),'max_ms':round(max(times),4)})
    return {'environment':{'python':platform.python_version(),'sqlite':__import__('sqlite3').sqlite_version,
                            'platform':platform.platform()},'results':results}
if __name__=='__main__':
    doc=run();print(json.dumps(doc,indent=2))
    out=pathlib.Path(__file__).parent
    (out/'bench_guard_results.json').write_text(json.dumps(doc,indent=2))
    with (out/'bench_guard_results.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=doc['results'][0].keys());w.writeheader();w.writerows(doc['results'])
