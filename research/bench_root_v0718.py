"""SHA-bound, separate-interpreter ABBA baseline against current root-controlled CAS status.
Measures only local status (no network, no disk power failure, no HSM).
"""
import csv,hashlib,json,os,pathlib,statistics,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parent
BASE=pathlib.Path('/mnt/data/equal3_v0717_review/Equal3_v0717_Research')
O=ROOT/'EVIDENCE_V0718';O.mkdir(exist_ok=True)
SRC=r'''
import tempfile,pathlib,time,json,statistics
from state_store import StateStore
from anchor_protocol import position_for_genesis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commit_evidence_v0716 import EvidenceRequiredCASAnchor
from __MODULE__ import __CLASS__
with tempfile.TemporaryDirectory() as folder:
 p=pathlib.Path(folder);a=p/'authority';a.mkdir(mode=0o700)
 s=StateStore.create(p/'state.db',key=b'K'*32,initial=b'init',journal_mode='DELETE')
 old=Ed25519PrivateKey.generate()
 if '__MODULE__' == 'trust_rotation_v0718':
  root=Ed25519PrivateKey.generate()
  backend=RootControlledCASAnchor.bootstrap(a/'a.db',position_for_genesis(s),reviewer_key=b'R'*32,seal_key=b'S'*32,
      attester_public_key=old.public_key(),deployment_id='prod-a',root_public_key=root.public_key())
 else:
  backend=EvidenceRequiredCASAnchor.bootstrap(a/'a.db',position_for_genesis(s),reviewer_key=b'R'*32,seal_key=b'S'*32,
      attester_public_key=old.public_key(),deployment_id='prod-a')
 for _ in range(40):backend.status()
 timings=[]
 for _ in range(400):
  start=time.perf_counter_ns();backend.status();timings.append((time.perf_counter_ns()-start)/1e6)
 print(json.dumps({'median_ms':statistics.median(timings),'p95_ms':sorted(timings)[int(len(timings)*.95)-1],
                  'count':len(timings)}))
'''
if not BASE.is_dir():raise SystemExit('baseline source path absent; cannot perform verified version comparison')
rows=[]
for roundno,(v1,v2) in enumerate([('baseline','candidate'),('candidate','baseline'),('candidate','baseline'),('baseline','candidate')],1):
 for v in (v1,v2):
  directory=BASE if v=='baseline' else ROOT
  name='commit_evidence_v0716' if v=='baseline' else 'trust_rotation_v0718'
  cls='EvidenceRequiredCASAnchor' if v=='baseline' else 'RootControlledCASAnchor'
  code=SRC.replace('__MODULE__',name).replace('__CLASS__',cls)
  output=subprocess.run([sys.executable,'-c',code],cwd=directory,capture_output=True,text=True,check=True,timeout=30)
  data=json.loads(output.stdout)
  file=directory/(name+'.py')
  row={'round':roundno,'variant':v,'source':str(file),'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),**data}
  rows.append(row);print(row,flush=True)
with (O/'benchmark_root_abba.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print('RESULT',json.dumps({v:{'median_of_round_medians_ms':statistics.median([x['median_ms'] for x in rows if x['variant']==v])} for v in ('baseline','candidate')}))
