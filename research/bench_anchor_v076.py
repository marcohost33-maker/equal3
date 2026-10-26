"""Synthetic v0.7.6 anchor CAS microbenchmark; no production SLO claim."""
from contextlib import closing
import csv
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import platform
import random
import secrets
import statistics
import subprocess
import sys
import tempfile
import time

from anchor_protocol import CoordinatedStore, MemoryCASAnchor, _review_message, position_for_genesis
from anchor_wire import PersistentCASAnchor, RPCAnchor
from state_store import StateStore, prepare_update


def percentile(a,p):
    xs=sorted(a)
    point=(len(xs)-1)*p/100
    i=int(point)
    return xs[i]+(xs[min(i+1,len(xs)-1)]-xs[i])*(point-i)


def probe(method,bytes_n,round_no,n=24):
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        st=StateStore.create(root/'store.sqlite', key=secrets.token_bytes(32), initial=b'')
        reviewer=secrets.token_bytes(32)
        seal=secrets.token_bytes(32)
        initial=position_for_genesis(st)
        proc=None
        if method=='memory':
            anchor=MemoryCASAnchor(initial,reviewer_key=reviewer,seal_key=seal,research_unsafe_sqlite=True)
        else:
            PersistentCASAnchor.bootstrap(root/'anchor.sqlite',initial,reviewer_key=reviewer,seal_key=seal,research_unsafe_sqlite=True)
            writer=secrets.token_bytes(32)
            for name,key in (('writer.key',writer),('review.key',reviewer)):
                fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as f:f.write(key)
            sock=root/'service.sock'
            proc=subprocess.Popen([sys.executable,'anchor_wire.py','--db',str(root/'anchor.sqlite'),
                '--socket',str(sock),'--writer-key-file',str(root/'writer.key'),
                '--reviewer-key-file',str(root/'review.key'),'--writer-uid',str(os.getuid())],
                cwd=str(Path(__file__).parent),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and not sock.exists() and proc.poll() is None:time.sleep(.02)
            if not sock.exists():raise RuntimeError('service startup failed')
            anchor=RPCAnchor(sock,writer_key=writer)
        client=CoordinatedStore(st,anchor)
        measurements=[]
        try:
            for i in range(n+5):
                data=hashlib.shake_256(f'{bytes_n}|{round_no}|{i}'.encode()).digest(bytes_n)
                proposal,_=prepare_update(st,data)
                t0=time.perf_counter_ns()
                client.apply(proposal)
                t1=time.perf_counter_ns()
                pending=anchor.status().pending
                token=(anchor.test_only_review_token(pending,'FINALIZE_COMMIT') if method=='memory'
                       else hmac.new(reviewer,_review_message(pending,'FINALIZE_COMMIT'),hashlib.sha256).digest())
                client.adjudicate('FINALIZE_COMMIT',token)
                t2=time.perf_counter_ns()
                assert client.diagnose().code=='MATCH'
                if i>=5:measurements.append({'apply_ms':(t1-t0)/1e6,'review_ms':(t2-t1)/1e6,'total_ms':(t2-t0)/1e6})
        finally:
            if proc is not None:
                proc.terminate()
                try:proc.wait(timeout=2)
                except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
        return measurements


def run(output):
    result=[]
    # ABBA layout, fixed payload corpus, second round reverses order.
    for round_no in (0,1):
        for bytes_n in (1024,65536):
            methods=['memory','rpc'] if round_no==0 else ['rpc','memory']
            for method in methods:
                times=probe(method,bytes_n,round_no)
                for index,ob in enumerate(times):result.append({'round':round_no+1,'payload_bytes':bytes_n,'method':method,'observation':index+1,**ob})
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    with (out/'benchmark_v076.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=result[0].keys());writer.writeheader();writer.writerows(result)
    summary=[]
    for n in (1024,65536):
        for meth in ('memory','rpc'):
            obs=[x for x in result if x['payload_bytes']==n and x['method']==meth]
            vals=[x['total_ms'] for x in obs]
            apps=[x['apply_ms'] for x in obs]
            summary.append({'payload_bytes':n,'method':meth,'n':len(obs),
                            'median_total_ms':round(statistics.median(vals),4),
                            'p95_total_ms':round(percentile(vals,95),4),
                            'median_apply_ms':round(statistics.median(apps),4),
                            'max_total_ms':round(max(vals),4)})
    d={'environment':{'python':sys.version.split()[0],'sqlite':__import__('sqlite3').sqlite_version,
          'platform':platform.platform()},
       'protocol':'v0.7.6 persistent local AF_UNIX research; reviewer token generation out-of-band simulated',
       'setup':'ABBA two rounds; each 5 warmup + 24 measured per method per payload; prep excluded; each commit includes manual review and diagnose of matching state; single host synthetic only',
       'summary':summary}
    (out/'benchmark_v076.json').write_text(json.dumps(d,indent=2)+'\n')
    for item in summary:print(item)

if __name__=='__main__':
    run(sys.argv[1] if len(sys.argv)>1 else 'EVIDENCE_V076')
