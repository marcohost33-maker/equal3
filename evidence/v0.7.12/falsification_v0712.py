"""Repeatable isolated negative-control probe for Equal3 StateStore.
Call: python falsification_v0712.py /path/to/v0711 /path/to/v0712 [outfile.json]
Each subprocess asserts its loaded source file identity to avoid benchmark drift.
"""
import json, os, pathlib, subprocess, sys
PROBE = r'''
import hashlib,json,sqlite3,sys,tempfile
from pathlib import Path
import state_store
assert Path(state_store.__file__).resolve() == Path(sys.argv[1]).resolve()
results={'loaded_source':str(Path(state_store.__file__).resolve())}
for count in (0,1):
 with tempfile.TemporaryDirectory() as t:
  store=state_store.StateStore.create(Path(t)/'db',key=b'K'*32,initial=b'known-original')
  if count:
   prop,_=state_store.prepare_update(store,b'known-committed')
   store.apply(prop)
  with sqlite3.connect(store.path) as db:
   db.execute('UPDATE head SET value=?,digest=? WHERE id=1',(b'forged-value',hashlib.sha256(b'forged-value').digest()))
  for method in ('read','verify','read_verified'):
   try:
    getattr(store,method)()
    result='ACCEPTED_FORGED_STATE'
   except Exception as e:
    result=type(e).__name__
   results[str(count)+'_receipts_'+method]=result
print(json.dumps(results,sort_keys=True))
'''
def main():
 if len(sys.argv) not in (3,4):
  raise SystemExit('Usage: falsification_v0712.py OLD_DIR NEW_DIR [OUT_JSON]')
 results={}
 for label,folder in (('v0711',sys.argv[1]),('v0712',sys.argv[2])):
  folder=pathlib.Path(folder).resolve();env=os.environ.copy();env['PYTHONPATH']=str(folder)
  output=subprocess.run([sys.executable,'-c',PROBE,str(folder/'state_store.py')],
      cwd=str(folder),env=env,text=True,capture_output=True,check=True,timeout=20)
  results[label]=json.loads(output.stdout)
 if len(sys.argv)==4:
  pathlib.Path(sys.argv[3]).write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
 print(json.dumps(results,indent=2,sort_keys=True))
if __name__=='__main__':main()
