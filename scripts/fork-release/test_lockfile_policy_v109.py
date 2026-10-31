"""Pure pnpm-dialect/graph admission regressions; no resolver or package code."""
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).with_name("lockfile_policy_v109.py")
if not P.is_file():
    P = Path(__file__).parents[1] / "pipeline/scripts/fork-release/lockfile_policy_v109.py"
s = importlib.util.spec_from_file_location("lock_policy", P)
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
NODE_SRI = "sha512-" + "A" * 86 + "=="
COMMON_SRI = "sha512-" + "B" * 86 + "=="


def lock(node="7.1.0", common="16.14.2", zod="4.6.6", extra="", bootstrap="pnpm-manager"):
    versions = {p: {"body-parser":"2.4.0", "qs":"6.16.1", "re2js":"2.8.7", "zod":zod,
        "undici":"8.12.2", "npm":"12.2.1", "vitest":"5.0.5", "fast-uri":"4.2.3",
        "nodemailer":"10.1.4"}[p] for p in m.CRITICAL}
    packages = "\n".join("  '" + p + "@" + v + "':\n    resolution: {integrity: " + NODE_SRI + "}\n"
        for p,v in versions.items())
    packages += "\n  '@azure/msal-node@"+node+"':\n    resolution: {integrity: "+NODE_SRI+"}\n"
    packages += "\n  '@azure/msal-common@"+common+"':\n    resolution: {integrity: "+COMMON_SRI+"}\n"+extra
    snapshots="\n".join("  '"+p+"@"+v+("(patch_hash="+m.ZOD_HASH+")" if p=="zod"else"")+"': {}"
        for p,v in versions.items())
    snapshots += "\n\n  '@azure/msal-node@"+node+"':\n    dependencies:\n      '@azure/msal-common': "+common+"\n"
    snapshots += "\n  '@azure/msal-common@"+common+"': {}\n"
    return ("---\nlockfileVersion: '9.0'\nimporters: {}\n# "+bootstrap+"\n\n---\n"
        "lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\n\npackages:\n\n"+packages+
        "\nsnapshots:\n\n"+snapshots).encode()


def browser_lock(upgraded=False):
    raw=lock("7.1.1","16.14.3") if upgraded else lock()
    package="\n  '@azure/msal-browser@5.24.0':\n    resolution: {integrity: "+NODE_SRI+"}\n"
    if upgraded:
        package+="\n  '@azure/msal-common@16.14.2':\n    resolution: {integrity: "+COMMON_SRI+"}\n"
    package+="\n  'fixture-tail@1.0.0': {}\n"
    raw=raw.replace(b"\nsnapshots:\n",package.encode()+b"\nsnapshots:\n")
    raw+=b"\n  '@azure/msal-browser@5.24.0':\n    dependencies:\n      '@azure/msal-common': 16.14.2\n\n"
    if upgraded:raw+=b"  '@azure/msal-common@16.14.2': {}\n"
    return raw.rstrip(b'\n')+b"\n\n  'fixture-tail@1.0.0': {}\n"


class LockPolicyTests(unittest.TestCase):
    def test_fixed_graph_upgrade_and_zod4_pass(self):
        result=m.verify_lock_security(lock(),lock("7.1.1","16.14.3"),NODE_SRI,COMMON_SRI)
        self.assertTrue(result["newUnpatchedZod3Absent"])
        self.assertFalse(result["unrelatedGeneratedDiffAutomaticallyApproved"])
        self.assertTrue(result["exactGeneratedDiffReviewRequiredBeforeCommit"])

    def test_zod3_new_resolution_refuses(self):
        for v in ("3.25.76","3.25.75"):
            with self.subTest(v=v),self.assertRaisesRegex(m.LockRefusal,"zod3"):
                m.verify_lock_security(lock(),lock("7.1.1","16.14.3",zod=v),NODE_SRI,COMMON_SRI)

    def test_extra_zod3_package_refuses(self):
        extra="\n  zod@3.25.76:\n    resolution: {integrity: "+NODE_SRI+"}\n"
        with self.assertRaisesRegex(m.LockRefusal,"zod3"):
            m.verify_lock_security(lock(),lock("7.1.1","16.14.3",extra=extra),NODE_SRI,COMMON_SRI)

    def test_bootstrap_document_is_byte_identical(self):
        with self.assertRaisesRegex(m.LockRefusal,"bootstrap_document"):
            m.verify_lock_security(lock(),lock("7.1.1","16.14.3",bootstrap="changed"),NODE_SRI,COMMON_SRI)

    def test_third_or_missing_document_refuses(self):
        for value in (lock()+b"\n---\nlockfileVersion: '9.0'\n",lock().split(b"---\n",2)[2]):
            with self.subTest(value=value[:20]),self.assertRaises(m.LockRefusal):m.documents(value)

    def test_duplicate_section_and_duplicate_entry_refuse(self):
        good=lock("7.1.1","16.14.3")
        for raw in (good+b"\npackages:\n",good.replace(b"  'zod@4.6.6':",b"  'zod@4.6.6':\n\n  'zod@4.6.6':")):
            with self.subTest(raw=raw[-30:]),self.assertRaises(m.LockRefusal):m.verify_lock_security(lock(),raw,NODE_SRI,COMMON_SRI)

    def test_wrong_node_or_common_version_refuses(self):
        for args in (("7.1.0","16.14.3"),("7.1.1","16.14.2"),("7.1.1","16.14.4")):
            with self.subTest(args=args),self.assertRaises(m.LockRefusal):m.verify_lock_security(lock(),lock(*args),NODE_SRI,COMMON_SRI)

    def test_wrong_integrity_refuses(self):
        with self.assertRaisesRegex(m.LockRefusal,"integrity_matches"):
            m.verify_lock_security(lock(),lock("7.1.1","16.14.3"),COMMON_SRI,NODE_SRI)

    def test_wrong_child_edge_refuses(self):
        bad=lock("7.1.1","16.14.3").replace(b"'@azure/msal-common': 16.14.3",b"'@azure/msal-common': 16.14.2")
        with self.assertRaisesRegex(m.LockRefusal,"parent_child"):
            m.verify_lock_security(lock(),bad,NODE_SRI,COMMON_SRI)

    def test_carried_critical_version_cannot_downgrade(self):
        bad=lock("7.1.1","16.14.3").replace(b"body-parser@2.4.0",b"body-parser@2.3.0")
        with self.assertRaisesRegex(m.LockRefusal,"security_versions"):
            m.verify_lock_security(lock(),bad,NODE_SRI,COMMON_SRI)

    def test_zod_patch_hash_cannot_change_or_disappear(self):
        good=lock("7.1.1","16.14.3")
        for bad in (good.replace(m.ZOD_HASH.encode(),b"a"*64),good.replace(("(patch_hash="+m.ZOD_HASH+")").encode(),b"")):
            with self.subTest(bad=bad[-40:]),self.assertRaisesRegex(m.LockRefusal,"patch_snapshot"):
                m.verify_lock_security(lock(),bad,NODE_SRI,COMMON_SRI)

    def test_browser_carried_common_and_upgraded_node_common_are_both_required(self):
        result=m.verify_lock_security(browser_lock(),browser_lock(True),NODE_SRI,COMMON_SRI)
        self.assertEqual(result['carriedMsalCommonConsumers'],{'@azure/msal-browser@5.24.0':'16.14.2'})
        self.assertEqual(result['selectedMsalCommonVersion'],'16.14.3')
        self.assertTrue(result['unexpectedMsalCommonConsumerAbsent'])
        self.assertFalse(result['unrelatedGeneratedDiffAutomaticallyApproved'])

    def test_new_common_consumer_is_not_approved(self):
        for child in ('16.14.2','16.14.3'):
            bad=browser_lock(True)+(f"\n  'unexpected@1.0.0':\n    dependencies:\n      '@azure/msal-common': {child}\n").encode()
            with self.subTest(child=child),self.assertRaisesRegex(m.LockRefusal,'parent_child'):
                m.verify_lock_security(browser_lock(),bad,NODE_SRI,COMMON_SRI)

    def test_unreviewed_carried_parent_is_not_approved(self):
        extra=b"\n  'unexpected@1.0.0':\n    dependencies:\n      '@azure/msal-common': 16.14.2\n"
        with self.assertRaisesRegex(m.LockRefusal,'carried_msal_common_consumers'):
            m.verify_lock_security(browser_lock()+extra,browser_lock(True)+extra,NODE_SRI,COMMON_SRI)

    def test_browser_edge_cannot_silently_upgrade_or_disappear(self):
        good=browser_lock(True)
        old=b"  '@azure/msal-browser@5.24.0':\n    dependencies:\n      '@azure/msal-common': 16.14.2"
        for new in (old.replace(b'16.14.2',b'16.14.3'),b"  '@azure/msal-browser@5.24.0': {}"):
            bad=good.replace(old,new)
            with self.assertRaisesRegex(m.LockRefusal,'parent_child'):
                m.verify_lock_security(browser_lock(),bad,NODE_SRI,COMMON_SRI)

    def test_old_node_edge_remains_forbidden_with_carried_browser(self):
        bad=browser_lock(True).replace(b"'@azure/msal-node@7.1.1':\n    dependencies:\n      '@azure/msal-common': 16.14.3",
            b"'@azure/msal-node@7.1.1':\n    dependencies:\n      '@azure/msal-common': 16.14.2")
        with self.assertRaisesRegex(m.LockRefusal,'parent_child'):
            m.verify_lock_security(browser_lock(),bad,NODE_SRI,COMMON_SRI)

    def test_carried_common_package_metadata_cannot_change(self):
        good=browser_lock(True)
        target=("  '@azure/msal-common@16.14.2':\n    resolution: {integrity: "+COMMON_SRI+"}").encode()
        for replacement in (target.replace(COMMON_SRI.encode(),NODE_SRI.encode()),target+b"\n    engines: {node: '>=999'}"):
            with self.assertRaisesRegex(m.LockRefusal,'carried_msal_common_unchanged'):
                m.verify_lock_security(browser_lock(),good.replace(target,replacement),NODE_SRI,COMMON_SRI)

    def test_carried_consumer_snapshot_or_integrity_cannot_change(self):
        good=browser_lock(True)
        package=("  '@azure/msal-browser@5.24.0':\n    resolution: {integrity: "+NODE_SRI+"}").encode()
        snapshot=b"  '@azure/msal-browser@5.24.0':\n    dependencies:\n      '@azure/msal-common': 16.14.2"
        for bad in (good.replace(package,package.replace(NODE_SRI.encode(),COMMON_SRI.encode())),
                    good.replace(snapshot,snapshot+b"\n      unexpected: 1.0.0")):
            with self.assertRaisesRegex(m.LockRefusal,'carried_msal_consumer_unchanged'):
                m.verify_lock_security(browser_lock(),bad,NODE_SRI,COMMON_SRI)

    def test_unconsumed_old_common_cannot_be_retained(self):
        bad=lock('7.1.1','16.14.3').replace(b'\nsnapshots:\n',
            ("\n  '@azure/msal-common@16.14.2':\n    resolution: {integrity: "+COMMON_SRI+"}\n\nsnapshots:\n").encode())
        bad+=b"\n  '@azure/msal-common@16.14.2': {}\n"
        with self.assertRaisesRegex(m.LockRefusal,'selected_msal_common'):
            m.verify_lock_security(lock(),bad,NODE_SRI,COMMON_SRI)

    def test_wrong_common_version_or_noncanonical_edge_refuses(self):
        good=browser_lock(True)
        for bad in (good.replace(b"'@azure/msal-common': 16.14.3",b"'@azure/msal-common': 16.14.4"),
                    good.replace(b"      '@azure/msal-common': 16.14.3",b"      @azure/msal-common: 16.14.3"),
                    good.replace(b"      '@azure/msal-common': 16.14.3",b"      '@azure/msal-common': 16.14.3\n      '@azure/msal-common': 16.14.3")):
            with self.assertRaises(m.LockRefusal):
                m.verify_lock_security(browser_lock(),bad,NODE_SRI,COMMON_SRI)


if __name__=="__main__":unittest.main()
