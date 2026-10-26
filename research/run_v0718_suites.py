"""Reproducible source-tree regression lanes; isolate multiprocessing lifetime."""
from pathlib import Path
import os,subprocess,sys,time,re,json
root=Path(__file__).resolve().parent
out=root/'EVIDENCE_V0718';out.mkdir(exist_ok=True)
groups={
 'anchor':['test_anchor_protocol','test_anchor_v077','test_anchor_v078','test_anchor_v079','test_anchor_wire'],
 'equal':['test_equal3','test_extensions','test_fault_lab','test_guarded_store','test_release_preflight_v078','test_v0713_rollback'],
 'store':['test_store','test_v07','test_v071','test_v0710_security','test_v0712_integrity','test_v074_hardening','test_witness'],
 'runtime':['test_runtime_gate_v0711','test_sqlite_build_v0711'],
 'writer':['test_writer_service_v0714'],
 'coordinator':['test_anchored_writer_v0715'],
 'attested':['test_attested_commit_v0716'],
 'policy':['test_attester_policy_v0717'],
 'root_rotation':['test_root_rotation_v0718'],
}
summary={};success=True
for name,group in groups.items():
 print('START',name,flush=True)
 started=time.monotonic()
 try:
  result=subprocess.run([sys.executable,'-W','error::ResourceWarning','-m','unittest','-q',*group],
      cwd=root,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=130)
  log=result.stdout+result.stderr
  match=re.search(r'Ran (\d+) tests? in ([\d.]+)s',log)
  ispass=result.returncode==0 and match is not None
  summary[name]={'status':'PASS' if ispass else 'FAIL','count':int(match.group(1)) if match else None,'time_s':round(time.monotonic()-started,3),'returncode':result.returncode}
 except subprocess.TimeoutExpired as exc:
  log=(exc.stdout.decode(errors='replace') if isinstance(exc.stdout,bytes) else (exc.stdout or ''))+'\nTIMEOUT'
  summary[name]={'status':'TIMEOUT','count':None,'time_s':round(time.monotonic()-started,3)}
  ispass=False
 (out/(name+'.log')).write_text(log)
 print(name,summary[name],flush=True)
 if not ispass:
  success=False
  print('FAIL TAIL',log[-2000:],flush=True)
  break
summary['total']=sum(x.get('count') or 0 for x in summary.values())
summary['all_pass']=success
(out/'suite_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('SUMMARY',json.dumps(summary),flush=True)
sys.exit(0 if success else 1)
