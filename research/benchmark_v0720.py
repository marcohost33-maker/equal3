"""Uncontended ABBA STATUS benchmark: historical core vs signed commit floor.

One Python process but same DB and v0720 code for both variants. Synthetic
research-only microbenchmark, not independent host or multiuser traffic.
"""
import csv,hashlib,json,statistics,time
from pathlib import Path
from anchored_writer_v0715 import AnchoredWriterCore
from external_commit_witness_v0720 import CommitGatedWriterCore
from test_external_commit_witness_v0720 import CommitWitnessTests,DEPLOY
from writer_service_v0714 import STATUS,ZERO_REQUEST

out=Path(__file__).parent/'EVIDENCE_V0720';out.mkdir(exist_ok=True)
rows=[]
for count in (1024,65536):
    t=CommitWitnessTests(methodName='runTest');t.setUp()
    try:
        intent=t.prepare(body=b'x'*count);t.finalize(intent);t.publish(intent,t.evidence(intent))
        plain=AnchoredWriterCore(t.store,t.anchor)
        guarded=CommitGatedWriterCore(t.store,t.anchor,commit_witness=t.client,deployment_id=DEPLOY)
        for roundnum,order in enumerate((('plain','guarded'),('guarded','plain'),('guarded','plain'),('plain','guarded'))):
            for name in order:
                core=plain if name=='plain' else guarded
                for _ in range(10):core.dispatch(STATUS,ZERO_REQUEST,b'')
                timings=[]
                for _ in range(80):
                    start=time.perf_counter_ns()
                    value=core.dispatch(STATUS,ZERO_REQUEST,b'')
                    elapsed=(time.perf_counter_ns()-start)/1e6
                    if not value['ok'] or value['version']!=1:raise RuntimeError('invalid status')
                    timings.append(elapsed)
                rows.append(dict(payload_bytes=count,round=roundnum,mode=name,
                    samples=len(timings),median_ms=round(statistics.median(timings),6),
                    p95_ms=round(sorted(timings)[int(.95*len(timings))-1],6),
                    max_ms=round(max(timings),6)))
    finally:t.doCleanups()
path=out/'benchmark_commit_floor_abba.csv'
with path.open('w',newline='') as f:
    writer=csv.DictWriter(f,fieldnames=rows[0].keys());writer.writeheader();writer.writerows(rows)
for n in (1024,65536):
    for name in ('plain','guarded'):
        med=statistics.median(row['median_ms'] for row in rows if row['payload_bytes']==n and row['mode']==name)
        print(n,name,round(med,4),'ms',flush=True)
print('benchmark_source_sha256',hashlib.sha256((Path(__file__).parent/'external_commit_witness_v0720.py').read_bytes()).hexdigest())
