"""ABBA synthetic benchmark. Only in-process direct API vs WriterCore; NO IPC."""
import argparse,csv,statistics,tempfile,time
from pathlib import Path
from state_store import StateStore,prepare_update
from writer_service_v0714 import WriterCore,SET
KEY=b'W'*32

def sample(kind,size,n):
    out=[]
    with tempfile.TemporaryDirectory() as tmp:
        store=StateStore.create(Path(tmp)/'test.sqlite',key=KEY,initial=b'a',journal_mode='DELETE')
        core=WriterCore(store)
        for i in range(n+5):
            data=bytes([65+i%25])*size
            rid=(i+1).to_bytes(16,'big')
            t=time.perf_counter_ns()
            if kind=='writer_core':core.dispatch(SET,rid,data)
            else:
                proposal,_=prepare_update(store,data,request_id=rid)
                store.apply(proposal)
            if i>=5:out.append((time.perf_counter_ns()-t)/1e6)
    return out

def run(n=20):
    records=[]
    for size in (1024,65536):
        for round_num,kind in enumerate(('direct','writer_core','writer_core','direct'),start=1):
            for i,latency in enumerate(sample(kind,size,n),start=1):
                records.append({'bytes':size,'round':round_num,'impl':kind,'iteration':i,'elapsed_ms':round(latency,7)})
    return records

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--iterations',type=int,default=20)
    a=p.parse_args()
    rows=run(a.iterations)
    with open(a.output,'w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['bytes','round','impl','iteration','elapsed_ms']);writer.writeheader();writer.writerows(rows)
    for size in (1024,65536):
        print('payload',size)
        for kind in ('direct','writer_core'):
            runs=[statistics.median(r['elapsed_ms'] for r in rows if r['bytes']==size and r['round']==n)
                  for n in (1,2,3,4) if (n in (1,4))==(kind=='direct')]
            print(kind,'round-median',runs,'median-of-medians',statistics.median(runs))
