"""Small synthetic ABBA microbenchmark. Not production SLA or trust-domain benchmark."""
from __future__ import annotations
import csv,hashlib,hmac,statistics,time,tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor_protocol import position_for_genesis,CoordinatedStore,_review_message
from anchor_wire import PersistentCASAnchor
from commit_evidence_v0716 import EvidenceRequiredCASAnchor,issue_observation
from anchored_writer_v0715 import AnchoredWriterCore
from state_store import StateStore
from writer_service_v0714 import SET

KEY=b'K'*32;REVIEW=b'R'*32;SEAL=b'S'*32

def trial(attested, size, sweep, repetitions=25):
    with tempfile.TemporaryDirectory() as td:
        p=Path(td);store=StateStore.create(p/'state.db',key=KEY,initial=b'i',journal_mode='DELETE')
        a=p/'anchor';a.mkdir(mode=0o700)
        signer=Ed25519PrivateKey.generate()
        anchor=(EvidenceRequiredCASAnchor.bootstrap(a/'db',position_for_genesis(store),reviewer_key=REVIEW,
                    seal_key=SEAL,attester_public_key=signer.public_key(),deployment_id='bench-lab')
                if attested else
                PersistentCASAnchor.bootstrap(a/'db',position_for_genesis(store),reviewer_key=REVIEW,seal_key=SEAL))
        c=AnchoredWriterCore(store,anchor);coord=CoordinatedStore(store,anchor)
        out=[]
        for i in range(repetitions+4):
            rid=(i+1).to_bytes(16,'big');body=bytes([i%251])*size
            start=time.perf_counter_ns()
            response=c.dispatch(SET,rid,body)
            assert not response['ok'] and response['assessment']=='COMMITTED_PENDING_HOLD'
            intent=anchor.status().pending
            token=hmac.new(REVIEW,_review_message(intent,'FINALIZE_COMMIT'),hashlib.sha256).digest()
            if attested:
                evidence=issue_observation(store=store,anchor=anchor,intent=intent,
                          decision='FINALIZE_COMMIT',deployment_id='bench-lab',signing_key=signer)
                after_observation=time.perf_counter_ns()
                assert coord.adjudicate('FINALIZE_COMMIT',token,evidence=evidence).code=='MATCH'
            else:
                after_observation=time.perf_counter_ns()
                assert coord.adjudicate('FINALIZE_COMMIT',token).code=='MATCH'
            assert c.dispatch(SET,rid,body)['ok']
            end=time.perf_counter_ns()
            if i>=4:
                out.append({'mode':'SIGNED_OBSERVATION' if attested else 'REVIEW_TOKEN_ONLY',
                            'payload_bytes':size,'sweep':sweep,'ordinal':i-3,
                            'total_ms':round((end-start)/1e6,6),
                            'observer_phase_ms':round((after_observation-start)/1e6,6)})
        return out

if __name__=='__main__':
    rows=[]
    for size in (1024,65536):
        for sweep,(m1,m2) in enumerate(((False,True),(True,False),(True,False),(False,True)),1):
            for att in (m1,m2):
                batch=trial(att,size,sweep)
                rows.extend(batch)
                print(size,sweep,att,'p50',round(statistics.median(x['total_ms'] for x in batch),3),'ms',flush=True)
    out=Path(__file__).resolve().parent/'EVIDENCE_V0716'/'benchmark_attestation_abba.csv'
    out.parent.mkdir(exist_ok=True)
    with out.open('w',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=list(rows[0]));wr.writeheader();wr.writerows(rows)
    for size in (1024,65536):
        for mode in ('REVIEW_TOKEN_ONLY','SIGNED_OBSERVATION'):
            m=[statistics.median(x['total_ms'] for x in rows if x['mode']==mode and x['payload_bytes']==size and x['sweep']==j) for j in (1,2,3,4)]
            print('SUMMARY',size,mode,'median of sweep medians',round(statistics.median(m),3))
