"""Comparative microbenchmark for authority state seals (synthetic; no power loss)."""
import csv
from contextlib import closing
import hashlib,hmac,importlib.util,os,secrets,sqlite3,statistics,tempfile,time
from pathlib import Path
from anchor_protocol import Position,Intent,_review_message
import anchor_wire as new

BASE=Path(__file__).resolve().parent/'REFERENCE_V076_anchor_wire.py'
spec=importlib.util.spec_from_file_location('original_anchor_wire_v076',BASE)
old=importlib.util.module_from_spec(spec); spec.loader.exec_module(old)


def percentile(vals,f):
    a=sorted(vals);idx=(len(a)-1)*f/100;l=int(idx);r=min(len(a)-1,l+1)
    return a[l]+(a[r]-a[l])*(idx-l)

def run(mode,cycle,n=60):
    with tempfile.TemporaryDirectory() as td:
        root=Path(td);os.chmod(root,0o700)
        db=root/'anchor.sqlite';reviewer=secrets.token_bytes(32);seal=secrets.token_bytes(32)
        pos=Position('a'*32,0,'b'*64)
        if mode=='v076':
            a=old.PersistentCASAnchor.bootstrap(db,pos,reviewer_key=reviewer)
        else:
            a=new.PersistentCASAnchor.bootstrap(db,pos,reviewer_key=reviewer,seal_key=seal,research_unsafe_sqlite=True)
        lat=[]; slat=[]
        # Warmup included as real state transitions, but excluded from measurements
        for k in range(n+5):
            p=a.status().committed
            i=Intent(p.store_id,p.version,p.digest,p.version+1,hashlib.sha256(f'v{k}'.encode()).hexdigest(),hashlib.md5(f'q{k}'.encode()).hexdigest(),hashlib.sha256(f'pkt{k}'.encode()).hexdigest())
            tok=hmac.new(reviewer,_review_message(i,'FINALIZE_COMMIT'),hashlib.sha256).digest()
            start=time.perf_counter_ns();a.prepare(i);a.adjudicate(i,'FINALIZE_COMMIT',tok)
            dt=(time.perf_counter_ns()-start)/1e6
            start=time.perf_counter_ns();st=a.status();status_ms=(time.perf_counter_ns()-start)/1e6
            assert st.pending is None and st.committed.version==k+1
            if k>=5:lat.append(dt);slat.append(status_ms)
        return [
            {'cycle':cycle,'version':mode,'method':'prepare_plus_finalize','n':n,'p50_ms':round(statistics.median(lat),5),'p95_ms':round(percentile(lat,95),5)},
            {'cycle':cycle,'version':mode,'method':'status','n':n,'p50_ms':round(statistics.median(slat),5),'p95_ms':round(percentile(slat,95),5)}]

def main():
    rows=[]
    for cycle,mode in enumerate(('v076','v077','v077','v076'),1):
        r=run(mode,cycle);rows.extend(r)
        print(mode,cycle,r,flush=True)
    with open('BENCHMARK_V077.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
if __name__=='__main__':main()
