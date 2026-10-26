"""Synthetic end-to-end dual Unix-socket benchmark; local same-UID test fixture.

Measures prepare+SQLite commit+out-of-band simulated reviewer finalize+retry
through writer RPC, which must not be confused with a production SLA.
"""
from __future__ import annotations
import csv,hashlib,hmac,json,os,pathlib,statistics,tempfile,threading,time
from anchor_protocol import CoordinatedStore,_review_message,position_for_genesis
from anchor_wire import PersistentCASAnchor,RPCAnchor,_UnixAuthority,_Handler as AnchorHandler
from anchored_writer_v0715 import AnchoredWriterCore
from state_store import StateStore
from writer_service_v0714 import _Server,_Handler as WriterHandler, client_request,SET

HERE=pathlib.Path(__file__).resolve().parent


def measure(size, n=12):
    with tempfile.TemporaryDirectory() as temp:
        root=pathlib.Path(temp);ad=root/'anchor';ad.mkdir(mode=0o700)
        sd=root/'state.db';store=StateStore.create(sd,key=b'K'*32,initial=b'old',journal_mode='DELETE')
        ae=ad/'anchor.db'; PersistentCASAnchor.bootstrap(ae,position_for_genesis(store),reviewer_key=b'R'*32,seal_key=b'S'*32)
        backend=PersistentCASAnchor(ae,reviewer_key=b'R'*32,seal_key=b'S'*32)
        a_socket=str(root/'anchor.sock'); w_socket=str(root/'writer.sock')
        with _UnixAuthority(a_socket,AnchorHandler) as authority:
            authority.backend=backend;authority.writer_uid=os.geteuid();authority.writer_key=b'P'*32
            at=threading.Thread(target=authority.serve_forever,daemon=True);at.start()
            try:
                rpc=RPCAnchor(a_socket,writer_key=b'P'*32)
                core=AnchoredWriterCore(store,rpc)
                with _Server(w_socket,WriterHandler) as writer:
                    writer.core=core;writer.writer_uid=os.geteuid()
                    wt=threading.Thread(target=writer.serve_forever,daemon=True);wt.start()
                    try:
                        samples=[]
                        for i in range(n):
                            rid=(i+1).to_bytes(16,'big');payload=bytes([i%256])*size
                            start=time.perf_counter_ns()
                            first=client_request(w_socket,op=SET,request_id=rid,target=payload)
                            assert first['assessment']=='COMMITTED_PENDING_HOLD',first
                            p=backend.status().pending
                            token=hmac.new(b'R'*32,_review_message(p,'FINALIZE_COMMIT'),hashlib.sha256).digest()
                            assert CoordinatedStore(store,rpc).adjudicate('FINALIZE_COMMIT',token).code=='MATCH'
                            final=client_request(w_socket,op=SET,request_id=rid,target=payload)
                            assert final['ok'] is True,final
                            samples.append((time.perf_counter_ns()-start)/1e6)
                        return samples
                    finally: writer.shutdown();wt.join(2)
            finally: authority.shutdown();at.join(2)


def main():
    dest=HERE/'EVIDENCE_V0715';dest.mkdir(exist_ok=True)
    rows=[];summary=[]
    for size in [1024,65536]:
        for round_no in range(2):
            for i,v in enumerate(measure(size)):
                rows.append({'bytes':size,'round':round_no,'index':i,'elapsed_ms':round(v,6)})
        data=[r['elapsed_ms'] for r in rows if r['bytes']==size]
        summary.append({'bytes':size,'count':len(data),'p50_ms':round(statistics.median(data),3),'p95_ms':round(sorted(data)[int(.95*(len(data)-1))],3)})
    with (dest/'benchmark_dual_ipc.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    (dest/'benchmark_dual_ipc_summary.json').write_text(json.dumps({'scope':'Two real Unix sockets with same-UID synthetic local authority and simulated reviewer; 24 commits/size; NO independent trust', 'results':summary},indent=2)+'\n')
    print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
