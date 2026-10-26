import unittest, tempfile, pathlib, secrets, os, shutil
import witness
from state_store import StateStore, prepare_update

class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.root=pathlib.Path(self.t.name)
        self.key=secrets.token_bytes(32); self.wkey=secrets.token_bytes(32)
        self.path=self.root/'primary.db'; self.wpath=self.root/'witness'/'anchor.txt'
        self.wpath.parent.mkdir()
        self.store=StateStore.create(self.path,key=self.key,initial=b'abc')
    def update(self,value):
        p,r=prepare_update(self.store,value)
        return self.store.apply(p)
    def test_init_match(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        self.assertEqual(witness.assess(self.store,self.wpath,self.wkey),'MATCH')
    def test_wrong_key_rejected(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        with self.assertRaises(witness.WitnessError): witness.read_witness(self.wpath,secrets.token_bytes(32))
    def test_duplicate_creation_rejected(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        with self.assertRaises(witness.WitnessError): witness.initialize(self.store,self.wpath,self.wkey)
    def test_ahead_detected(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        self.update(b'new')
        with self.assertRaises(witness.AheadOfWitness): witness.assess(self.store,self.wpath,self.wkey)
    def test_advance_accepts_match(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        self.update(b'new')
        self.assertEqual(witness.advance(self.store,self.wpath,self.wkey),'ADVANCED')
        self.assertEqual(witness.assess(self.store,self.wpath,self.wkey),'MATCH')
        self.assertEqual(witness.advance(self.store,self.wpath,self.wkey),'UNCHANGED')
    def test_rollback_restored_backup_detected(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        backup=self.root/'old.sqlite'; self.store.backup_verified(backup)
        self.update(b'def');witness.advance(self.store,self.wpath,self.wkey)
        self.store=None
        for suffix in ('','-wal','-shm'):
            p=pathlib.Path(str(self.path)+suffix)
            if p.exists():p.unlink()
        shutil.copy2(backup,self.path)
        restored=StateStore(self.path,key=self.key)
        with self.assertRaises(witness.RollbackDetected): witness.assess(restored,self.wpath,self.wkey)
    def test_joint_rollback_not_detected_expected_limitation(self):
        # A correctly authenticated OLD witness restored WITH an old DB can pass.
        # This falsifies "local signed witness alone gives absolute anti-rollback".
        witness.initialize(self.store,self.wpath,self.wkey)
        old_witness=self.wpath.read_bytes()
        backup=self.root/'old-all.sqlite';self.store.backup_verified(backup)
        self.update(b'new');witness.advance(self.store,self.wpath,self.wkey)
        self.store=None
        for suffix in ('','-wal','-shm'):
            p=pathlib.Path(str(self.path)+suffix)
            if p.exists():p.unlink()
        shutil.copy2(backup,self.path)
        self.wpath.write_bytes(old_witness)
        old=StateStore(self.path,key=self.key)
        self.assertEqual(witness.assess(old,self.wpath,self.wkey),'MATCH')

    def test_corrupted_tag_detected(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        data=bytearray(self.wpath.read_bytes()); data[-2]=ord('0') if data[-2]!=ord('0') else ord('1');self.wpath.write_bytes(data)
        with self.assertRaises(witness.WitnessError): witness.assess(self.store,self.wpath,self.wkey)
    def test_wrong_store_detected(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        other=StateStore.create(self.root/'other.db',key=self.key,initial=b'abc')
        with self.assertRaises(witness.ForkDetected): witness.assess(other,self.wpath,self.wkey)
    def test_version_equal_digest_conflict(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        c=witness.read_witness(self.wpath,self.wkey)
        fake=witness.Checkpoint(c.store_id,c.version,'0'*64)
        self.wpath.write_bytes(witness._pack(fake,self.wkey))
        with self.assertRaises(witness.ForkDetected): witness.assess(self.store,self.wpath,self.wkey)
    def test_noncanonical_json_rejected(self):
        witness.initialize(self.store,self.wpath,self.wkey)
        w=self.wpath.read_bytes()
        self.wpath.write_bytes(w.replace(b'"version":0',b'"version": 0'))
        with self.assertRaises(witness.WitnessError): witness.read_witness(self.wpath,self.wkey)

if __name__=='__main__':unittest.main()
