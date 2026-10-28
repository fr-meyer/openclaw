"""Real tiny Git trees prove the five-file test-only equivalence boundary."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import test_source_validation_v108 as support

driver=support.driver


class SuccessorWitnessTests(unittest.TestCase):
    def repo(self,root):
        env={"PATH":os.environ["PATH"],"HOME":str(root),"GIT_CONFIG_NOSYSTEM":"1",
             "GIT_CONFIG_GLOBAL":"/dev/null","GIT_AUTHOR_NAME":"Synthetic fixture",
             "GIT_AUTHOR_EMAIL":"fixture@invalid","GIT_COMMITTER_NAME":"Synthetic fixture",
             "GIT_COMMITTER_EMAIL":"fixture@invalid","GIT_OPTIONAL_LOCKS":"0"}
        def git(*args):return subprocess.check_output(["git","-C",str(root),*args],env=env,stderr=subprocess.DEVNULL).decode().strip()
        git("init","-q")
        for name in [*driver.TEST_ONLY_PATHS,"src/runtime.ts","pnpm-lock.yaml","patches/worker.patch"]:
            f=root/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text("inert fixture data\n")
        # Use the real length/object framing rather than a made-up object pin.
        data=b"inert fixture data\n";blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        ledger={"schema":"synthetic-ledger","unchanged":{"origin":"fixed"},"paths":[
            {"path":name,"result":{"mode":"100644","blob":blob},"disposition":"FIXTURE","origin":None}
            for name in sorted(driver.TEST_ONLY_PATHS)]}
        path=root/driver.DERIVED_LEDGER_PATH;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(ledger,sort_keys=True))
        git("add",".");git("commit","-qm","fixture baseline")
        return git,env,git("rev-parse","HEAD"),git("rev-parse","HEAD^{tree}")
    def invoke(self,mutation=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);git,env,parent,tree=self.repo(root)
            target="src/commands/doctor-config-preflight.process.test.ts"
            if mutation=="indirect":
                (root/target).write_text("first inert change\n");git("add",".");git("commit","-qm","intermediate")
            (root/target).write_text("changed inert test fixture\n")
            ledger_path=root/driver.DERIVED_LEDGER_PATH;ledger=json.loads(ledger_path.read_text())
            row=next(row for row in ledger["paths"] if row["path"]==target)
            data=(root/target).read_bytes();row["result"]["blob"]=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
            if mutation=="ledger-origin":row["origin"]="forged"
            elif mutation=="ledger-disposition":row["disposition"]="forged"
            elif mutation=="ledger-rowset":ledger["paths"].pop(0)
            elif mutation=="ledger-blob":row["result"]["blob"]="0"*40
            if mutation!="missing-ledger":ledger_path.write_text(json.dumps(ledger,sort_keys=True))
            if mutation=="ledger-mode":ledger_path.chmod(0o755)
            if mutation=="outside":(root/"src/runtime.ts").write_text("outside change\n")
            elif mutation=="lock":(root/"pnpm-lock.yaml").write_text("dependency identity change\n")
            elif mutation=="patch":(root/"patches/worker.patch").write_text("patch identity change\n")
            elif mutation=="added":(root/"new.test.ts").write_text("added\n")
            elif mutation=="deleted":(root/"src/runtime.ts").unlink()
            elif mutation=="mode":(root/target).chmod(0o755)
            git("add",".");git("commit","-qm","test-only successor")
            current=git("rev-parse","HEAD")
            raw=subprocess.check_output(["git","-C",str(root),"ls-tree","-r","-z",parent],env=env)
            rows=[]
            for row in raw.split(b"\0"):
                if row and row.split(b"\t",1)[1].decode() not in (target,driver.DERIVED_LEDGER_PATH):rows.append(row)
            raw=b"".join(row+b"\0" for row in sorted(rows,key=lambda r:r.split(b"\t",1)[1]))
            witness={"schema":"openclaw.v108.test-only-successor.v1","parentSha":parent,"parentTree":tree,
                     "changedPaths":[target],"unchangedTreeSha256":hashlib.sha256(raw).hexdigest()}
            if mutation=="digest":witness["unchangedTreeSha256"]="0"*64
            elif mutation=="omitted":witness["changedPaths"]=[]
            req={"sourceWitness":witness,"firstSourceSha":parent,"firstSourceTree":tree,"sourceSha":current}
            return driver.verify_test_only_successor(root,req),parent,current
    def test_direct_test_only_successor_preserves_old_receipt_identity(self):
        receipt,parent,current=self.invoke()
        self.assertEqual(receipt["reusedReceiptSourceSha"],parent)
        self.assertEqual(receipt["currentSourceSha"],current)
        self.assertFalse(receipt["sameSourceReceiptRelabeled"])
    def test_changed_runtime_lock_patch_added_deleted_mode_indirect_or_digest_refuse(self):
        for mutation in ("outside","lock","patch","added","deleted","mode","indirect","digest","omitted",
                         "ledger-origin","ledger-disposition","ledger-rowset","ledger-blob","ledger-mode","missing-ledger"):
            with self.subTest(mutation=mutation),self.assertRaises(driver.release.Refusal):self.invoke(mutation)
    def test_required_affected_profiles_fit_individually_but_combined_changes_refuse(self):
        first="d"*40;current="c"*40;tree="e"*40
        with patch.multiple(driver,SOURCE=current,TREE=tree,FIRST_SOURCE=first,FIRST_TREE=tree):
            for path,profiles,minutes in [
                ("src/commands/doctor-config-preflight.process.test.ts",["types-tests","doctor-1","doctor-2","doctor-3"],250),
                ("src/gateway/server-managed-task-flow-runtime.mergeguez-parity.test.ts",["types-tests","sqlite"],175),
                ("test/v108-remediation-security.test.mjs",["types-tests","dependency","compatibility"],235)]:
                req=support.request(3,profiles,[*driver.RETAINED_SOURCE_RUN_IDS,"998"])
                req.update(sourceSha=current,sourceWitness={"schema":"openclaw.v108.test-only-successor.v1",
                    "parentSha":first,"parentTree":tree,"changedPaths":[path],"unchangedTreeSha256":"f"*64})
                self.assertEqual(driver.round_minutes(driver.validate_request(req)),minutes)
                req["profiles"]=profiles[1:]
                with self.assertRaises(driver.release.Refusal):driver.validate_request(req)
            req=support.request(3,["types-tests","doctor-1","doctor-2","doctor-3","dependency","compatibility"],[*driver.RETAINED_SOURCE_RUN_IDS,"998"])
            req.update(sourceSha=current,sourceWitness={"schema":"openclaw.v108.test-only-successor.v1",
                "parentSha":first,"parentTree":tree,"changedPaths":sorted(["src/commands/doctor-config-preflight.process.test.ts","test/v108-remediation-security.test.mjs"]),"unchangedTreeSha256":"f"*64})
            with self.assertRaises(driver.release.Refusal):driver.validate_request(req)

if __name__=="__main__":unittest.main()
