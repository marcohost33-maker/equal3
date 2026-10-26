"""Equal3 replay/read verification microbenchmark. No release-grade throughput claim."""
from pathlib import Path
import csv, hashlib, os, statistics, sys, tempfile, time
from state_store import StateStore, prepare_update

source_hash=hashlib.sha256(Path(__import__('state_store').__file__).read_bytes()).hexdigest()
label=sys.argv[1]
out=Path(sys.argv[2])
records=[]
with tempfile.TemporaryDirectory(prefix='eq-bench-') as tmp:
 for depth in (1,50,250):
  s=StateStore.create(Path(tmp)/f'store_{depth}.sqlite',key=b'M'*32,initial=b'init')
  first,rid=prepare_update(s,b'A'*128); s.apply(first)
  for i in range(1,depth):
   p,_=prepare_update(s,(f'state-{i:04d}'.encode()*15)); s.apply(p)
  for method in ('receipt','idempotent_apply'):
   def fn():return s.receipt(rid) if method=='receipt' else s.apply(first)
   for _ in range(3):fn()
   samples=[]
   for _ in range(20):
    t=time.perf_counter_ns();r=fn(); samples.append((time.perf_counter_ns()-t)/1e6)
    assert r.version==1 and r.already_committed
   records.append({'version':label,'source_sha256':source_hash,'history_length':depth,
       'method':method,'n':len(samples), 'median_ms':round(statistics.median(samples),5),
       'p95_ms':round(sorted(samples)[-2],5),'min_ms':round(min(samples),5),'max_ms':round(max(samples),5)})
with out.open('w',newline='') as f:
 writer=csv.DictWriter(f,fieldnames=records[0]);writer.writeheader();writer.writerows(records)
print('\n'.join(f"{r['version']} {r['history_length']} {r['method']}: {r['median_ms']} ms" for r in records))
