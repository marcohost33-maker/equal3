from __future__ import annotations
import json,os,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parent
E=ROOT/'EVIDENCE_V0716';E.mkdir(exist_ok=True)
GROUPS={
 'anchor':['test_anchor_protocol','test_anchor_v077','test_anchor_v078','test_anchor_v079','test_anchor_wire'],
 'equal':['test_equal3','test_extensions','test_fault_lab','test_guarded_store','test_release_preflight_v078','test_v0713_rollback'],
 'store':['test_store','test_v07','test_v071','test_v0710_security','test_v0712_integrity','test_v074_hardening','test_witness'],
 'runtime':['test_runtime_gate_v0711','test_sqlite_build_v0711'],
 'protected_writer':['test_writer_service_v0714'],
 'new_coordinated_writer':['test_anchored_writer_v0715'],
 'attested_gate':['test_attested_commit_v0716'],
}
report={}
for name,group in GROUPS.items():
    command=[sys.executable,'-W','error::ResourceWarning','-m','unittest','-q',*group]
    started=time.monotonic()
    print(f'RUN {name}',flush=True)
    try:
        result=subprocess.run(command,cwd=ROOT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=115)
        output=result.stdout+result.stderr
        match=re.search(r'Ran (\d+) tests? in ([\d.]+)s',output)
        status='PASS' if result.returncode==0 and match else 'FAIL'
        report[name]={'tests':int(match.group(1)) if match else None,'status':status,'returncode':result.returncode,'seconds':round(time.monotonic()-started,3)}
    except subprocess.TimeoutExpired as exc:
        output=(exc.stdout or b'').decode(errors='replace') if isinstance(exc.stdout,bytes) else (exc.stdout or '')
        output+='\nTIMEOUT';report[name]={'tests':None,'status':'TIMEOUT','seconds':round(time.monotonic()-started,3)}
    (E/(name+'_tests.log')).write_text(output)
    print(name,report[name],flush=True)
    if report[name]['status'] != 'PASS':
        print(output[-1000:],flush=True)
        break
(E/'suite_summary.json').write_text(json.dumps(report,indent=2)+'\n')
print('RESULT',json.dumps(report),flush=True)
