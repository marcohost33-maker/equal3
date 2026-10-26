"""Research-only benchmark: compares unlike workflows, never claims production SLA.

Direct WriterCore: local apply; coordinated AnchoredWriterCore: prepare + DB
commit + external (synthetic) review + verified retry.  Source/hash and raw
samples are retained.  No real human review, independent HSM, or real multi-UID.
"""
from __future__ import annotations
import csv, hashlib, json, os, pathlib, random, statistics, tempfile, time
from state_store import StateStore
from writer_service_v0714 import WriterCore, SET
from anchored_writer_v0715 import AnchoredWriterCore
from anchor_protocol import MemoryCASAnchor, CoordinatedStore, position_for_genesis

ROOT=pathlib.Path(__file__).absolute().parent
KEY=b'K'*32

def run(path,kind, size, reps=20):
    store=StateStore.create(path,key=KEY,initial=b'initial',journal_mode='DELETE')
    if kind=='direct': core=WriterCore(store)
    else:
        anchor=MemoryCASAnchor(position_for_genesis(store),reviewer_key=b'R'*32)
        core=AnchoredWriterCore(store,anchor)
        reviewer=CoordinatedStore(store,anchor)
    observations=[]
    for i in range(reps):
        rid=(i+1).to_bytes(16,'big')
        body=bytes([i%256])*size
        t=time.perf_counter_ns()
        first=core.dispatch(SET,rid,body)
        if kind=='coordinated':
            assert first['ok'] is False and first['assessment']=='COMMITTED_PENDING_HOLD',first
            intent=anchor.status().pending
            token=anchor.test_only_review_token(intent,'FINALIZE_COMMIT')
            assert reviewer.adjudicate('FINALIZE_COMMIT',token).code=='MATCH'
            last=core.dispatch(SET,rid,body)
            assert last['ok'] is True
        else:assert first['ok'] is True
        observations.append((time.perf_counter_ns()-t)/1e6)
    return observations

def main():
    rows=[]; random.seed(20261025)
    for size in [1024,65536]:
        for sweep, order in enumerate((['direct','coordinated'], ['coordinated','direct'], ['direct','coordinated'], ['coordinated','direct'])):
            for kind in order:
                with tempfile.TemporaryDirectory() as d:
                    results=run(pathlib.Path(d)/'store.db',kind,size)
                for i,v in enumerate(results):rows.append(dict(size=size,sweep=sweep,mode=kind,index=i,elapsed_ms=round(v,6)))
    dest=ROOT/'EVIDENCE_V0715';dest.mkdir(exist_ok=True)
    with (dest/'benchmark_writer_full_protocol.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    summ=[]
    for size in [1024,65536]:
        for mode in ('direct','coordinated'):
            data=[r['elapsed_ms'] for r in rows if r['size']==size and r['mode']==mode]
            summ.append({'bytes':size,'mode':mode,'count':len(data),'p50_ms':round(statistics.median(data),3),
                         'p95_ms':round(sorted(data)[int(.95*(len(data)-1))],3)})
    summary={'method':'4 sweeps ABBA, 20 independent operations per sweep, 1 KiB/64 KiB','synthetic':True,
        'benchmarks':summ,'sources':{k:hashlib.sha256((ROOT/k).read_bytes()).hexdigest() for k in ('writer_service_v0714.py','anchored_writer_v0715.py','anchor_protocol.py','state_store.py')}}
    (dest/'benchmark_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summ,indent=2))
if __name__=='__main__':main()
