"""Negative-first: equal version/digest do not imply equal committed request identity."""
import shutil
import unittest
from pathlib import Path
from anchor_protocol import AnchorHold, MemoryCASAnchor, CoordinatedStore
from state_store import StateStore, prepare_update
from external_commit_witness_v0720 import CommitGatedWriterCore
import test_external_commit_witness_v0720 as fixtures

class CommitRequestBindingTests(unittest.TestCase):
    setUp=fixtures.CommitWitnessTests.setUp
    close=fixtures.CommitWitnessTests.close
    prepare=fixtures.CommitWitnessTests.prepare
    finalize=fixtures.CommitWitnessTests.finalize
    evidence=fixtures.CommitWitnessTests.evidence
    publish=fixtures.CommitWitnessTests.publish
    floor=fixtures.CommitWitnessTests.floor

    def test_different_request_same_digest_at_same_version_must_hold(self):
        i=self.prepare(body=b'next', rid=b'A'*16)
        self.finalize(i);self.publish(i,self.evidence(i))
        other_path=self.base/'other.db'
        shutil.copyfile(self.genesis_backup,other_path)
        other_store=StateStore(other_path,key=fixtures.KEY,journal_mode='DELETE')
        other_anchor=MemoryCASAnchor(self.genesis,reviewer_key=fixtures.REVIEW)
        other=CoordinatedStore(other_store,other_anchor)
        prop,_=prepare_update(other_store,b'next',request_id=b'B'*16)
        other.apply(prop)
        pending=other_anchor.status().pending
        other.adjudicate('FINALIZE_COMMIT',other_anchor.test_only_review_token(pending,'FINALIZE_COMMIT'))
        self.assertEqual(i.version,pending.version)
        self.assertEqual(i.digest,pending.digest)
        self.assertNotEqual(i.request_id,pending.request_id)
        self.assertEqual(other.diagnose().code,'MATCH')
        with self.assertRaises(AnchorHold):
            CommitGatedWriterCore(other_store,other_anchor,commit_witness=self.client,deployment_id=fixtures.DEPLOY)

    def test_matching_request_identity_is_accepted(self):
        i=self.prepare(body=b'next',rid=b'A'*16);self.finalize(i);self.publish(i,self.evidence(i))
        g=CommitGatedWriterCore(self.store,self.anchor,commit_witness=self.client,deployment_id=fixtures.DEPLOY)
        from writer_service_v0714 import STATUS,ZERO_REQUEST
        self.assertEqual(g.dispatch(STATUS,ZERO_REQUEST,b'')['version'],1)

    def test_genesis_without_request_identity_is_accepted(self):
        g=CommitGatedWriterCore(self.store,self.anchor,commit_witness=self.client,deployment_id=fixtures.DEPLOY)
        from writer_service_v0714 import STATUS,ZERO_REQUEST
        self.assertEqual(g.dispatch(STATUS,ZERO_REQUEST,b'')['version'],0)

if __name__=='__main__':unittest.main()
