"""Real temporary Git-tree regression for reviewed H3 material additions.

No application, package, network, or production operation is performed.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

import source_validation_contract_v109 as p
import source_validation_v108 as core

ADDED = "scripts/lib/npm-glob-vendor-proof.mjs"


class ReviewedMaterialAdditionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="reviewed-material-tree-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.env = {**os.environ,"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
            "GIT_NO_LAZY_FETCH":"1","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0"}
        self.command = ["git","--no-replace-objects","-c","protocol.allow=never","-c","core.hooksPath=/dev/null",
            "-c","user.name=Synthetic Fixture","-c","user.email=fixture@example.invalid","-C",str(self.root)]
        self.git("init","--object-format=sha1","--quiet")
        self.write("package.json",b'{"name":"synthetic-base"}\n')
        self.write(p.LEDGER,b'{"fixture":"base"}\n')
        self.write("keep.txt",b"preserved fixture\n")
        self.git("add","--","package.json",p.LEDGER,"keep.txt")
        self.git("commit","--no-gpg-sign","--quiet","-m","synthetic base")
        self.before_commit = self.git("rev-parse","HEAD").decode().strip()
        tree = self.git("rev-parse","HEAD^{tree}").decode().strip()
        self.before = core._v4_tree(self.git,self.before_commit,tree)

    def git(self,*args):
        return subprocess.run(self.command+list(args),capture_output=True,check=True,timeout=15,env=self.env).stdout

    def write(self,name,raw):
        target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)

    def finish(self,declared):
        self.git("add","-A","--",".")
        self.git("commit","--no-gpg-sign","--quiet","-m","synthetic reviewed step")
        commit=self.git("rev-parse","HEAD").decode().strip()
        tree=self.git("rev-parse","HEAD^{tree}").decode().strip()
        after=core._v4_tree(self.git,commit,tree)
        step={"source":{"sourceSha":commit},"changedPaths":sorted(declared),
            "contentSha256":{name:p.digest(self.git("show",commit+":"+name)) if name in after else "0"*64 for name in declared},
            "unchangedTreeSha256":p.tree_digest(self.before,declared)}
        return after,step

    def verified(self,after,step):
        return p._verify_reviewed_step(self.git,self.before,after,step,
            allowed_additions=set(step["changedPaths"]) & p.H3_MATERIAL_PATHS)

    def test_authorized_regular_addition_passes_real_git_tree(self):
        self.write(ADDED,b"export const syntheticProof = true;\n")
        self.write(p.LEDGER,b'{"fixture":"next"}\n')
        after,step=self.finish({ADDED,p.LEDGER})
        self.assertIsNone(self.verified(after,step))
        self.assertEqual(after[ADDED][:2],("100644","blob"))
        with self.assertRaisesRegex(ValueError,"corrected_source_path_set"):
            p._verify_reviewed_step(self.git,self.before,after,step)  # old callers remain equal-path only

    def test_undeclared_extra_addition_refuses(self):
        self.write(ADDED,b"export const syntheticProof = true;\n")
        self.write("extra-unreviewed.mjs",b"unreviewed\n")
        after,step=self.finish({ADDED})
        with self.assertRaises(ValueError):self.verified(after,step)

    def test_declared_but_unapproved_addition_refuses_even_explicit_argument(self):
        self.write("unapproved.mjs",b"unreviewed\n")
        after,step=self.finish({"unapproved.mjs"})
        with self.assertRaisesRegex(ValueError,"reviewed_addition_scope"):
            p._verify_reviewed_step(self.git,self.before,after,step,allowed_additions={"unapproved.mjs"})

    def test_removal_refuses(self):
        (self.root/"keep.txt").unlink()
        after,step=self.finish({"keep.txt"})
        with self.assertRaisesRegex(ValueError,"corrected_source_path_set"):
            self.verified(after,step)

    def test_executable_added_mode_refuses(self):
        self.write(ADDED,b"export const syntheticProof = true;\n")
        (self.root/ADDED).chmod(0o755)
        after,step=self.finish({ADDED})
        with self.assertRaisesRegex(ValueError,"exact_reviewed_correction_paths"):
            self.verified(after,step)

    def test_symlink_alias_addition_refuses(self):
        target=self.root/ADDED;target.parent.mkdir(parents=True,exist_ok=True)
        target.symlink_to("../../keep.txt")
        after,step=self.finish({ADDED})
        self.assertEqual(after[ADDED][0],"120000")
        with self.assertRaisesRegex(ValueError,"exact_reviewed_correction_paths"):
            self.verified(after,step)

    def test_existing_mode_drift_refuses(self):
        (self.root/"package.json").chmod(0o755)
        after,step=self.finish({"package.json"})
        with self.assertRaisesRegex(ValueError,"exact_reviewed_correction_paths"):
            self.verified(after,step)

    def test_content_hash_drift_refuses(self):
        self.write(ADDED,b"export const syntheticProof = true;\n")
        after,step=self.finish({ADDED});step["contentSha256"][ADDED]="0"*64
        with self.assertRaisesRegex(ValueError,"exact_reviewed_correction_bytes"):
            self.verified(after,step)

    def test_existing_equal_path_correction_remains_valid(self):
        self.write("package.json",b'{"name":"synthetic-updated"}\n')
        after,step=self.finish({"package.json"})
        self.assertIsNone(p._verify_reviewed_step(self.git,self.before,after,step))


if __name__=="__main__":unittest.main()
