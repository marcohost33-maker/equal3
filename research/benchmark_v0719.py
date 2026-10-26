"""Local research microbenchmark: v0718 static floor vs live signed epoch witness."""
import csv,hashlib,json,statistics,time
from pathlib import Path
from test_external_epoch_witness_v0719 import WitnessTests
from trust_rotation_v0718 import RootControlledCASAnchor
ROOT=Path(__file__).resolve().parent
out=ROOT/'EVIDENCE_V0719';out.mkdir(exist_ok=True)
fixture=WitnessTests('test_genesis_live_remote_challenge')
fixture.setUp()
try:
 static=RootControlledCASAnchor(fixture.local,reviewer_key=b'R'*32,seal_key=b'S'*32,
        attester_public_key=fixture.old.public_key(),root_public_key=fixture.root.public_key(),
        deployment_id='main-prod-research',min_epoch=0)
 live=fixture.gated()
 versions={'static':static,'witnessed':live}
 rows=[]
 for round_index,order in enumerate((('static','witnessed'),('witnessed','static'),('static','witnessed'),('witnessed','static')),1):
  for label in order:
   obj=versions[label]
   for _ in range(40):obj.status()
   vals=[]
   for _ in range(160):
    t0=time.perf_counter_ns();obj.status();vals.append((time.perf_counter_ns()-t0)/1e6)
   vs=sorted(vals)
   rows.append(dict(round=round_index,mode=label,n=len(vals),p50_ms=statistics.median(vals),p95_ms=vs[int(.95*(len(vs)-1))],
       source_sha256=hashlib.sha256((ROOT/('external_epoch_witness_v0719.py' if label=='witnessed' else 'trust_rotation_v0718.py')).read_bytes()).hexdigest()))
 with (out/'benchmark_epoch_witness.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
 sums={k:statistics.median(r['p50_ms'] for r in rows if r['mode']==k) for k in versions}
 print(json.dumps({'median_round_medians_ms':sums,'ratio':sums['witnessed']/sums['static'],'qualifier':'same-host local Unix socket and same UID; no independent host/network, no production SLA'},indent=2))
finally:
 fixture.doCleanups()
