"""Controlled synthetic comparison within same candidate source; no production SLA."""
import csv, hashlib, os, random, sqlite3, statistics, tempfile, time
from pathlib import Path
from state_store import StateStore, prepare_update

KEY=b'Q'*32
ROUNDS=[('WAL','DELETE'),('DELETE','WAL'),('DELETE','WAL'),('WAL','DELETE')]

def run(payload,mode,round_id):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'store.sqlite'
        s=StateStore.create(p,key=KEY,initial=b'A'*payload,journal_mode=mode)
        reads=[];writes=[]
        for i in range(36):
            data=bytes([(i+1)%200+35])+b'A'*(payload-1)
            proposal,_=prepare_update(s,data)
            t=time.perf_counter_ns();s.apply(proposal);ms=(time.perf_counter_ns()-t)/1e6
            r=time.perf_counter_ns();snap=s.read();rd=(time.perf_counter_ns()-r)/1e6
            assert snap.value==data
            if i>=6:writes.append(ms);reads.append(rd)
        return [dict(mode=mode,payload_bytes=payload,round=round_id,operation='apply',median_ms=statistics.median(writes),p95_ms=sorted(writes)[int(.95*(len(writes)-1))],measurements=len(writes)),dict(mode=mode,payload_bytes=payload,round=round_id,operation='read',median_ms=statistics.median(reads),p95_ms=sorted(reads)[int(.95*(len(reads)-1))],measurements=len(reads))]

def main():
    rows=[]
    for payload in (1024,65536):
        for round_id,pair in enumerate(ROUNDS,1):
            for mode in pair:
                rows.extend(run(payload,mode,round_id))
    out=Path(__file__).parent/'EVIDENCE_V0713'/'journal_benchmark.csv';out.parent.mkdir(exist_ok=True)
    with out.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
    for p in (1024,65536):
        for op in ('apply','read'):
            d={m:statistics.median([x['median_ms'] for x in rows if x['mode']==m and x['payload_bytes']==p and x['operation']==op]) for m in ('WAL','DELETE')}
            print(f'{p}B {op}: WAL={d["WAL"]:.3f} ms DELETE={d["DELETE"]:.3f} ms ratio={d["DELETE"]/d["WAL"]:.2f}x')
    print('csv='+str(out));print('sqlite_runtime='+sqlite3.sqlite_version)
if __name__=='__main__':main()
