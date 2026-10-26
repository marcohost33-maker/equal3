"""Deterministic adversarial clock transition across signature verification and CAS."""
import unittest
from unittest import mock
from external_commit_witness_v0720 import verify_final_checkpoint
import test_external_commit_witness_v0720 as fixtures
from anchor_protocol import ReviewDenied
import external_commit_witness_v0720 as w

class CommitWitnessExpiryTests(unittest.TestCase):
    setUp=fixtures.CommitWitnessTests.setUp
    close=fixtures.CommitWitnessTests.close
    prepare=fixtures.CommitWitnessTests.prepare
    finalize=fixtures.CommitWitnessTests.finalize
    evidence=fixtures.CommitWitnessTests.evidence
    publish=fixtures.CommitWitnessTests.publish
    floor=fixtures.CommitWitnessTests.floor
    def test_signed_observation_expired_after_verify_before_commit_is_denied(self):
        intent=self.prepare()
        self.finalize(intent)
        evidence=self.evidence(intent)
        now=evidence['statement']['issued_unix']
        real=w.verify_final_checkpoint
        def verify_then_expire(*a,**k):
            real(*a,**{**k,'now':now})
            clock['value']=now+61
        clock={'value':now}
        with mock.patch.object(w,'verify_final_checkpoint',side_effect=verify_then_expire),mock.patch.object(w.time,'time',side_effect=lambda:clock['value']):
            with self.assertRaises(ReviewDenied):self.ledger.publish(intent,evidence)
        self.assertEqual(self.floor()['version'],0)
    def test_post_final_still_current_can_publish(self):
        intent=self.prepare();self.finalize(intent);self.publish(intent,self.evidence(intent))
        self.assertEqual(self.floor()['version'],1)

if __name__=='__main__':unittest.main()
