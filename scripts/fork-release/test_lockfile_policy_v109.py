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




class H3LockPolicyTests(unittest.TestCase):
    def context(self):
        import json
        proof=P.parent/"candidates/v2026.10.9-source-only/h3-selected-excluded-ages.json"
        value = {"amendmentSha256":m.authority.H3_AMENDMENT_SHA256,"sourceGeneration":1,
            "checkedAt":m.authority.H3_NOT_BEFORE,"packageBytes":json.dumps({"dependencies":{"minimatch":"11.0.1"}}).encode(),
            "fileTransferPackageBytes":json.dumps({"dependencies":{"minimatch":"11.0.1"}}).encode(),
            "workspaceBytes":b'minimumReleaseAge: 10080\nminimumReleaseAgeStrict: true\noverrides:\n  follow-redirects: 1.16.2\n  "mailauth@7.1.0>joi": 18.3.1\n  minimatch: 11.0.1\n  "cacache@21.0.1>glob": 14.0.2\n',
            "excludedAgeProofBytes":proof.read_bytes(),"excludedAgeProofSha256":m.H3_EXCLUDED_AGE_PROOF_SHA256,
            "targetMetadataProofBytes":(P.parent/"candidates/v2026.10.9-source-only/h3-target-package-metadata.json").read_bytes(),
            "targetMetadataProofSha256":m.H3_TARGET_METADATA_PROOF_SHA256}
        excludes=["@openai/codex","@openai/codex-*"]+[row["name"]+"@"+row["version"] for row in json.loads(value["excludedAgeProofBytes"])["tuples"] if row["name"].startswith("@openclaw/fs-safe")]
        block="minimumReleaseAgeExclude:\n"+"".join('  - "'+name+'"\n' for name in excludes)
        value["workspaceBytes"]=value["workspaceBytes"].replace(b"overrides:\n",block.encode()+b"overrides:\n")
        return value
    def graph(self, upgraded):
        import json
        base=lock("7.1.1","16.14.3").decode()
        extra_packages="";extra_snapshots=""
        versions={name:pair[1 if upgraded else 0] for name,pair in m.H3_TARGETS.items()}
        target_metadata={row["name"]:row for row in json.loads(self.context()["targetMetadataProofBytes"])["tuples"]}
        for name,version in versions.items():
            integrity=target_metadata[name]["integrity"] if upgraded else NODE_SRI
            extra_packages+="\n  '"+name+"@"+version+"':\n    resolution: {integrity: "+integrity+"}\n"
            extra_snapshots+="\n  '"+name+"@"+version+"': {}\n"
        for row in json.loads(self.context()["excludedAgeProofBytes"])["tuples"]:
            key=row["name"]+"@"+row["version"]
            extra_packages+="\n  '"+key+"':\n    resolution: {integrity: "+row["integrity"]+"}\n"
            extra_snapshots+="\n  '"+key+"': {}\n"
        for parent,child in (("mailauth@7.1.0","joi"),("cacache@21.0.1","glob")):
            extra_packages+="\n  '"+parent+"':\n    resolution: {integrity: "+NODE_SRI+"}\n"
            extra_snapshots+="\n  '"+parent+"':\n    dependencies:\n      "+child+": "+versions[child]+"\n"
        overrides="\noverrides:\n  follow-redirects: "+versions["follow-redirects"]+"\n  minimatch: "+versions["minimatch"]+"\n"
        if upgraded:overrides+="  'mailauth@7.1.0>joi': 18.3.1\n  'cacache@21.0.1>glob': 14.0.2\n"
        importers="\nimporters:\n\n  .:\n    dependencies:\n      minimatch:\n        specifier: "+versions["minimatch"]+"\n        version: "+versions["minimatch"]+"\n\n  extensions/file-transfer:\n    dependencies:\n      minimatch:\n        specifier: "+versions["minimatch"]+"\n        version: "+versions["minimatch"]+"\n"
        overrides += "  undici@>=8.0.0 <8.12.2: 8.12.2\n  zod@>=4.0.0 <4.6.6: 4.6.6\n"
        head,body=base.rsplit("---\n",1)
        body=body.replace("\npackages:\n",overrides+importers+"\npackages:\n")
        body=body.replace("\npackages:\n", "\npackageExtensionsChecksum: sha256-" + "A" * 43 + "=\n\npackages:\n")
        body=body.replace("\nsnapshots:\n",extra_packages+"\nsnapshots:\n")+extra_snapshots
        return (head+"---\n"+body).encode()
    def verify(self, raw=None, context=None):
        return m.verify_lock_security(self.graph(False),self.graph(True) if raw is None else raw,NODE_SRI,COMMON_SRI,h3=self.context() if context is None else context)
    def test_h3_exact_four_pins_parent_selectors_and_age_proof(self):
        got=self.verify();self.assertEqual(got["sourceSuccessor"]["excludedSelectedTupleCount"],18)
        self.assertFalse(got["unrelatedGeneratedDiffAutomaticallyApproved"])
    def test_h3_wrong_selectors_refuse(self):
        for before,after in ((b"mailauth@7.1.0>joi",b"mailauth@7.0.0>joi"),(b"cacache@21.0.1>glob",b"glob")):
            h=self.context();h["workspaceBytes"]=h["workspaceBytes"].replace(before,after)
            with self.subTest(before=before),self.assertRaises(m.LockRefusal):self.verify(context=h)
    def test_h3_wrong_target_or_stale_h2_lock_refuses(self):
        for raw in (self.graph(False),self.graph(True).replace(b"joi@18.3.1",b"joi@18.3.0")):
            with self.subTest(raw=raw[-30:]),self.assertRaises(m.LockRefusal):self.verify(raw)
    def test_h3_scalar_checksum_change_or_duplicate_refuses(self):
        raw = self.graph(True)
        checksum = b"packageExtensionsChecksum: sha256-" + b"A" * 43 + b"="
        for bad in (raw.replace(checksum, checksum.replace(b"A", b"B")),
                    raw.replace(checksum, checksum + b"\n" + checksum)):
            with self.subTest(bad=bad[:80]), self.assertRaises(m.LockRefusal):
                self.verify(bad)

    def test_h3_scalar_checksum_continuation_or_nested_body_refuses(self):
        raw = self.graph(True)
        checksum = b"packageExtensionsChecksum: sha256-" + b"A" * 43 + b"="
        for body in (b"  continuation", b"  arbitrary: nested"):
            with self.subTest(body=body), self.assertRaises(m.LockRefusal):
                self.verify(raw.replace(checksum, checksum + b"\n" + body))

    def test_h3_scalar_checksum_removal_or_malformed_refuses(self):
        raw = self.graph(True)
        checksum = b"packageExtensionsChecksum: sha256-" + b"A" * 43 + b"="
        for bad in (raw.replace(checksum + b"\n", b""),
                    raw.replace(checksum, b"packageExtensionsChecksum: invalid")):
            with self.subTest(bad=bad[:80]), self.assertRaises(m.LockRefusal):
                self.verify(bad)

    def test_h3_exact_existing_range_override_values_cannot_change(self):
        raw = self.graph(True)
        for bad in (raw.replace(b"undici@>=8.0.0 <8.12.2: 8.12.2", b"undici@>=8.0.0 <8.12.2: 8.12.1"),
                    raw.replace(b"zod@>=4.0.0 <4.6.6: 4.6.6", b"zod@>=4.0.0 <4.6.6: 4.6.5")):
            with self.subTest(bad=bad[:80]), self.assertRaises(m.LockRefusal):
                self.verify(bad)

    def test_h3_duplicate_or_unknown_unquoted_range_selector_refuses(self):
        raw = self.graph(True)
        line = b"  undici@>=8.0.0 <8.12.2: 8.12.2\n"
        for bad in (raw.replace(line, line + line),
                    raw.replace(line, b"  undici@>=8.0.0 <8.12.3: 8.12.2\n")):
            with self.subTest(bad=bad[:80]), self.assertRaises(m.LockRefusal):
                self.verify(bad)

    def test_h3_unrelated_integrity_and_graph_drift_refuse(self):
        raw=self.graph(True)
        for bad in (raw.replace(b"'mailauth@7.1.0':\n    resolution: {integrity: "+NODE_SRI.encode()+b"}",b"'mailauth@7.1.0':\n    resolution: {integrity: "+COMMON_SRI.encode()+b"}"),raw+b"\n  'unrelated@1.0.0': {}\n"):
            with self.assertRaises(m.LockRefusal):self.verify(bad)
    def test_h3_unknown_excluded_tuple_wrong_integrity_or_absence_refuse(self):
        raw=self.graph(True)
        for bad in (raw.replace(b"@openai/codex@0.160.0-darwin-arm64",b"@openai/codex@0.160.1-darwin-arm64"),raw.replace(b"@openai/codex@0.160.0'",b"@openai/codex@0.160.1'")):
            with self.assertRaises(m.LockRefusal):self.verify(bad)
        h=self.context();h["excludedAgeProofBytes"]=h["excludedAgeProofBytes"]+b" "
        with self.assertRaises(m.LockRefusal):self.verify(context=h)
    def test_h3_no_package_use_before_conservative_floor(self):
        h=self.context();h["checkedAt"]="2026-11-04T09:59:49Z"
        with self.assertRaises(m.LockRefusal):m.verify_h3_before_package_use(self.graph(False),h)
    def test_h3_positive_selected_exclusion_check_is_not_fullclosure_claim(self):
        got=m.verify_h3_before_package_use(self.graph(False),self.context())
        self.assertEqual(got["excludedSelectedTupleCount"],18);self.assertFalse(got["fullResolvedClosureProven"])
    def test_h3_cannot_weaken_global_age_policy(self):
        for before,after in ((b"10080",b"0"),(b"Strict: true",b"Strict: false")):
            h=self.context();h["workspaceBytes"]=h["workspaceBytes"].replace(before,after)
            with self.assertRaises(m.LockRefusal):self.verify(context=h)
    def test_h3_direct_minimatch_both_consumers_required(self):
        for key in ("packageBytes","fileTransferPackageBytes"):
            h=self.context();h[key]=h[key].replace(b"11.0.1",b"10.2.6")
            with self.assertRaises(m.LockRefusal):self.verify(context=h)
    def test_h3_wrong_or_unbound_authority_refuses(self):
        for key,value in (("amendmentSha256","0"*64),("sourceGeneration",4),("sourceGeneration",True)):
            h=self.context();h[key]=value
            with self.assertRaises(m.LockRefusal):self.verify(context=h)


class H3RetainedDeprecationTests(unittest.TestCase):
    context = H3LockPolicyTests.context
    verify = H3LockPolicyTests.verify
    CORE_INTEGRITY = "sha512-i4YPS4B6ts7bjn7UwLnGjiZdprOvHvgGobFZsYK3GIY3E5hIqtj0rReU69BcTpGp+fvtraSNXeG1l+jtJvF55w=="
    WARNING = "Deprecated due to a bug in custom logger data redaction. See https://github.com/aws/aws-sdk-js-v3/issues/8393."

    def graph(self, upgraded):
        raw = H3LockPolicyTests.graph(self, upgraded)
        package = ("\n  '@smithy/core@3.35.1':\n    resolution: {integrity: " + self.CORE_INTEGRITY + "}\n    engines: {node: '>=18.0.0'}\n")
        return raw.replace(b"\nsnapshots:\n", package.encode() + b"\nsnapshots:\n") + b"\n  '@smithy/core@3.35.1': {}\n"

    def warning_lock(self):
        marker = b"    engines: {node: '>=18.0.0'}\n"
        return self.graph(True).replace(marker, marker + ("    deprecated: " + self.WARNING + "\n").encode())

    def test_authentic_warning_addition_is_preserved_without_version_change(self):
        raw = self.warning_lock()
        got = self.verify(raw)
        self.assertIn(("    deprecated: " + self.WARNING).encode(), raw)
        self.assertFalse(got["unrelatedGeneratedDiffAutomaticallyApproved"])
        self.assertTrue(got["exactGeneratedDiffReviewRequiredBeforeCommit"])

    def test_unknown_warning_or_other_package_cannot_use_exception(self):
        raw = self.warning_lock()
        for bad in (raw.replace(self.WARNING.encode(), b"different warning"),
                    raw.replace(b"@smithy/core@3.35.1", b"@smithy/core@3.35.2"),
                    raw.replace(b"@smithy/core@3.35.1", b"@different/core@3.35.1")):
            with self.subTest(bad=bad[-100:]), self.assertRaises(m.LockRefusal):
                self.verify(bad)

    def test_warning_does_not_allow_integrity_engines_or_snapshot_drift(self):
        raw = self.warning_lock()
        for bad in (raw.replace(self.CORE_INTEGRITY.encode(), NODE_SRI.encode()),
                    raw.replace(b"engines: {node: '>=18.0.0'}", b"engines: {node: '>=999'}"),
                    raw.replace(b"  '@smithy/core@3.35.1': {}", b"  '@smithy/core@3.35.1':\n    dependencies:\n      unexpected: 1.0.0")):
            with self.subTest(bad=bad[-100:]), self.assertRaises(m.LockRefusal):
                self.verify(bad)

    def test_duplicate_deprecation_field_refuses(self):
        line = ("    deprecated: " + self.WARNING + "\n").encode()
        with self.assertRaises(m.LockRefusal):
            self.verify(self.warning_lock().replace(line, line + line))

    def test_preexisting_warning_cannot_be_removed_or_changed(self):
        old = self.warning_lock()
        for bad in (self.graph(True), old.replace(self.WARNING.encode(), b"different warning")):
            with self.subTest(bad=bad[-100:]), self.assertRaises(m.LockRefusal):
                m.verify_lock_security(old, bad, NODE_SRI, COMMON_SRI, h3=self.context())


if __name__=="__main__":unittest.main()
