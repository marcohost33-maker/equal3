"""Isolated-process regression; never infer success from missing/timeout output."""
from pathlib import Path
import os,subprocess,sys,time,re,json
root=Path(__file__).resolve().parent
out=root/'EVIDENCE_V0721';out.mkdir(exist_ok=True)
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
 'external_witness':['test_external_epoch_witness_v0719'],
 'commit_witness':['test_external_commit_witness_v0720'],
 'expiry_v0721':['test_commit_floor_expiry_v0721'],
}
summary={};success=True
for name,group in groups.items():
 print('START',name,flush=True)
 start=time.monotonic()
 try:
  result=subprocess.run([sys.executable,'-W','error::ResourceWarning','-m','unittest','-q',*group],
      cwd=root,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=145)
  log=result.stdout+result.stderr
  match=re.search(r'Ran (\d+) tests? in ([\d.]+)s',log)
  good=result.returncode==0 and match is not None
  summary[name]={'status':'PASS' if good else 'FAIL','count':int(match.group(1)) if match else None,
                 'elapsed_seconds':round(time.monotonic()-start,3),'returncode':result.returncode}
 except subprocess.TimeoutExpired as exc:
  log=(exc.stdout.decode(errors='replace') if isinstance(exc.stdout,bytes) else (exc.stdout or ''))+'\nTIMEOUT'
  good=False
  summary[name]={'status':'TIMEOUT','count':None,'elapsed_seconds':round(time.monotonic()-start,3)}
 (out/(name+'.log')).write_text(log)
 print(name,summary[name],flush=True)
 if not good:
  success=False;print('ERROR TAIL',log[-2000:],flush=True);break
summary['all_pass']=success and len(summary)==len(groups)
summary['total']=sum(summary[k].get('count') or 0 for k in groups if k in summary)
(out/'suite_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('SUMMARY',json.dumps(summary),flush=True)
sys.exit(0 if summary['all_pass'] else 1)
