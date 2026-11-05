"""Synthetic protocol regressions, not compiler/package or hosted CI proof."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import base64
import hashlib
import json
import socket
import subprocess
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

import npm_vendor_derivation_v109 as v
import source_validation_contract_v109 as p
import source_validation_v109 as controller


def need(value, code):
    if not value:
        raise ValueError(code)


def proof_fixture():
    # Synthetic files isolate the protocol owner. No candidate package is loaded.
    rows = [{"path": "synthetic/f%04d" % i, "mode": 0o644, "size": 1, "sha256": "a" * 64} for i in range(1938)]
    rows += [{"path": name, "mode": 0o644, "size": 1, "sha256": "b" * 64} for name in v.JS_MEMBERS]
    rows.sort(key=lambda row: row["path"])
    inventory_sha = v.digest(json.dumps(rows, separators=(",", ":")).encode() + b"\n")
    text = "".join("diff --git a/{0} b/{0}\n--- a/{0}\n+++ b/{0}\n@@ -1,1 +1,1 @@\n-a\n+b\n".format(name) for name in v.JS_MEMBERS)
    patch_bytes = text.encode()
    changes = [{"path": name, "oldSha256": "b" * 64, "newSha256": v.digest(name.encode()), "size": 2, "mode": 0o644} for name in v.JS_MEMBERS]
    changed = {row["path"]: row for row in changes}
    derived = [dict(row) for row in rows]
    for row in derived:
        if row["path"] in changed:
            row["sha256"] = changed[row["path"]]["newSha256"]
            row["size"] = changed[row["path"]]["size"]
    value = {"schema": v.PROOF_SCHEMA, "npmVersion": "12.2.1", "original": {
        "integrity": v.ORIGINAL_SRI, "sha256": v.ORIGINAL_SHA256,
        "inventorySha256": inventory_sha, "mapsAbsent": True, "files": rows}, "repair": {
        "globVersion": "13.0.6", "fixCommit": v.FIX_COMMIT, "sourceCommit": v.SOURCE_COMMIT,
        "sourceSha256": "ae534f35edd3837a2969ecdd4ea90853cc1b9a9c8e4d10108e5e0994fb5e001e",
        "upstreamFixSha256": "22adee340137e4f0636701c99bb5f75fb572d38c91ff5de0b77b80f453c18e4a", "changedFiles": changes},
        "compiler": {"name": "esbuild", "version": "0.28.2", "integrity": v.ESBUILD_SRI},
        "derived": {"integrity": "sha512-" + base64.b64encode(bytes(64)).decode(), "sha256": "c" * 64,
            "inventorySha256": v.digest(json.dumps(derived, separators=(",", ":")).encode() + b"\n")},
        "patch": {"filename": Path(v.PATCH).name, "sha256": v.digest(patch_bytes), "size": len(patch_bytes)},
        "maps": [{"path": name + ".map", "size": 1, "sha256": "d" * 64} for name in v.JS_MEMBERS]}
    return value, patch_bytes, inventory_sha


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def qualification_fixture(record):
    receipt = {"schema":"openclaw.npm-glob-vendor-qualification.v1", "status":"passed", "phase":"complete", "reason":"all_52_cases_passed",
        "packageExecuted":True, "imageTested":False, "actualBunRuntimeTested":False,
        "proofSha256":record["proofSha256"], "patchSha256":record["patchSha256"], "originalSha256":v.ORIGINAL_SHA256,
        "derivedSha256":"c"*64, "packageExecutionAttempted":True, "tests":{
            "schema":"openclaw.npm-vendor-actual-package-tests.v1", "passed":True,
            "caseCount":52,"passedCount":52,"cases":[{"name":"synthetic-case-%d"%i,"passed":True} for i in range(52)],
            "packageExecutionHost":"ci-only","imageTested":False,"publicPackTested":True,"actualBunRuntimeTested":False},
        "testResultEvidence":{"file":"npm-vendor-actual-test-result.private.json","bytes":1,"sha256":"a"*64,"storedBytes":1,
            "storedSha256":"a"*64,"truncated":False,"limitBytes":131072}}
    return {"schema":"openclaw.v109.npm-vendor-qualification-evidence.v1","qualifierRuntimeSha256":"d"*64,
        "receiptSha256":v.digest(encoded(receipt)),"receipt":receipt,"controls":[{"path":name,"runtimeSha256":"e"*64,"receiptSha256":"f"*64,
            "caseCount":count,"passedCount":count,"exitCode":0,"timedOut":False,"cleanupSettled":None} for name,count in v.CONTROL_TESTS]}


class VendorProtocolTests(unittest.TestCase):
    def setUp(self):
        for obj, name in ((subprocess, "Popen"), (socket, "socket")):
            guard = patch.object(obj, name, side_effect=AssertionError("no real process/network")); guard.start(); self.addCleanup(guard.stop)

    def test_workspace_adds_only_exact_npm_entry(self):
        before = b"minimumReleaseAge: 10080\npatchedDependencies:\n  zod@4.6.6: patches/zod.patch\nother: true\n"
        after = v.expected_workspace(before, need)
        self.assertEqual(after, before.replace(b"patchedDependencies:\n", b"patchedDependencies:\n  npm@12.2.1: patches/npm@12.2.1.patch\n"))
        self.assertEqual(v.expected_workspace(after, need), after)

    def test_workspace_duplicate_missing_or_different_npm_refuses(self):
        for raw in (b"x: 1\n", b"patchedDependencies:\npatchedDependencies:\n", b"patchedDependencies:\n  npm@12.2.1: patches/other.patch\n", b"patchedDependencies:\n  npm@12.2.1: patches/npm@12.2.1.patch\n  npm@12.2.1: patches/npm@12.2.1.patch\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError): v.expected_workspace(raw, need)

    def test_fixed_four_regular_patch_members(self):
        _, raw, _ = proof_fixture(); self.assertEqual(v.validate_patch(raw, need), raw)
        for wrong in (raw.replace(b"walker.js", b"walker.js.map"), raw.replace(b"--- a/", b"--- /dev/null"), raw + b"new file mode 100644\n"):
            with self.assertRaises(ValueError): v.validate_patch(wrong, need)

    def test_exact_proof_and_record_roundtrip(self):
        proof, raw_patch, inventory = proof_fixture()
        with patch.object(v, "ORIGINAL_INVENTORY_SHA256", inventory):
            raw = encoded(proof); self.assertEqual(v.validate_proof(raw, raw_patch, need), proof)
            before = b"patchedDependencies:\n  zod@4.6.6: patches/zod.patch\n"
            workspace = v.expected_workspace(before, need)
            record = v.make_record(2, workspace, raw_patch, raw, b"producer", need)
            self.assertEqual(v.verify_files(record, before, workspace, raw_patch, raw, b"producer", need), record)
            with self.assertRaises(ValueError): v.verify_files(record, before, workspace + b"unsafe: true\n", raw_patch, raw, b"producer", need)
            with self.assertRaises(ValueError): v.verify_files(record, before, workspace, raw_patch, raw, b"other-producer", need)

    def test_proof_rejects_wrong_original_fix_compiler_and_unrelated_inventory(self):
        original, raw_patch, inventory = proof_fixture()
        mutations = [lambda x: x["original"].update(mapsAbsent=False), lambda x: x["repair"].update(globVersion="14.0.2"),
            lambda x: x["repair"].update(fixCommit="a" * 40), lambda x: x["compiler"].update(version="latest"),
            lambda x: x["original"]["files"][0].update(sha256="e" * 64), lambda x: x["repair"]["changedFiles"].pop(),
            lambda x: x["derived"].update(inventorySha256="f" * 64), lambda x: x["maps"].append({"path":"extra","size":1,"sha256":"f"*64})]
        with patch.object(v, "ORIGINAL_INVENTORY_SHA256", inventory):
            for mutate in mutations:
                value = deepcopy(original); mutate(value)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError): v.validate_proof(encoded(value), raw_patch, need)

    def test_proof_duplicate_keys_and_noncanonical_encoding_refuse(self):
        value, raw_patch, inventory = proof_fixture()
        with patch.object(v, "ORIGINAL_INVENTORY_SHA256", inventory):
            raw = encoded(value)
            for wrong in (raw.replace(b'"npmVersion": "12.2.1",', b'"npmVersion": "12.2.1", "npmVersion": "12.2.1",', 1), json.dumps(value).encode(), raw.replace(b'"mapsAbsent": true', b'"mapsAbsent": NaN')):
                with self.assertRaises(ValueError): v.validate_proof(wrong, raw_patch, need)

    def test_record_generation_types_and_unknown_keys_refuse(self):
        good = {"schema": v.SCHEMA, "sourceGeneration": 2, "workspaceSha256": "a" * 64, "patchSha256": "b" * 64, "proofSha256": "c" * 64, "producerRuntimeSha256": "d" * 64}
        self.assertIs(v.validate_record(good, need), good)
        for bad in ({**good, "sourceGeneration": True}, {**good, "sourceGeneration": 1}, {**good, "extra": 0}, {**good, "patchSha256": "x" * 64}):
            with self.assertRaises(ValueError): v.validate_record(bad, need)

    def test_lock_transform_removes_only_fixed_npm_patch(self):
        old = b"patchedDependencies:\n  zod@4.6.6: zzz\nimporters:\n  .:\n    dependencies:\n      npm:\n        specifier: 12.2.1\n        version: 12.2.1\npackages:\n  npm@12.2.1: unchanged\nsnapshots:\n  npm@12.2.1: {}\n"
        sha = "b" * 64; suffix = "(patch_hash=" + sha + ")"
        new = old.decode().replace("patchedDependencies:\n", "patchedDependencies:\n  npm@12.2.1: " + sha + "\n").replace("version: 12.2.1\n", "version: 12.2.1" + suffix + "\n").replace("  npm@12.2.1: {}", "  npm@12.2.1" + suffix + ": {}")
        self.assertEqual(v.unpatched_lock(old, new.encode(), sha, need), old)
        self.assertEqual(v.unpatched_lock(new.encode(), new.encode(), sha, need), new.encode())  # unchanged G3 patch needs no fake delta
        tampered = new.replace("unchanged", "UNRELATED")
        self.assertNotEqual(v.unpatched_lock(old, tampered.encode(), sha, need), old)  # existing graph comparison must still refuse it
        for bad in (new.replace(sha, "c" * 64, 1), new + "extra: 12.2.1" + suffix + "\n", new.replace("npm@12.2.1" + suffix + ": {}", "npm@12.2.1" + suffix + ": changed")):
            with self.assertRaises(ValueError): v.unpatched_lock(old, bad.encode(), sha, need)

    def test_derived_ledger_adds_only_fixed_regular_output_rows(self):
        old = {"schema": "openclaw.v109.fork-carry-reconciliation.v1", "lockState": "pending_ci_derivation", "sourcePaths": [
            {"path": "pnpm-lock.yaml", "result": {"mode": "100644", "blob": "a" * 40}},
            {"path": "pnpm-workspace.yaml", "result": {"mode": "100644", "blob": "b" * 40}}]}
        gen = {"runId": "123456", "runAttempt": 1, "pipelineHead": "c" * 40, "artifactId": 1,
            **{name: "d" * 64 for name in ("artifactSha256", "receiptSha256", "generatedLockSha256", "gitDiffSha256")}}
        entries = {name: {"mode": "100644", "blob": "e" * 40} for name in v.GENERATED}
        result = p.parse(p.expected_derived_ledger(p.encode(old), "f" * 40, gen, entries))
        self.assertEqual(set(row["path"] for row in result["sourcePaths"]), {"pnpm-lock.yaml", *v.GENERATED})
        for bad in ({**entries, "arbitrary": entries[v.PATCH]}, {**entries, v.PATCH: {"mode": "120000", "blob": "e" * 40}}):
            with self.assertRaises(ValueError): p.expected_derived_ledger(p.encode(old), "f" * 40, gen, bad)

    def test_family_requires_vendor_record_and_preserves_g1_shape(self):
        def source(sha, tree, package="1", workspace="2", lock="3", ledger="4"):
            result = deepcopy(p.H3_ANCHOR)
            result.update(sourceSha=sha * 40, sourceTree=tree * 40, manifestSha256="e" * 64, inventorySha256="f" * 64)
            result["fileSha256"] = {"package.json": package * 64, "pnpm-workspace.yaml": workspace * 64,
                "pnpm-lock.yaml": lock * 64, p.LEDGER: ledger * 64}
            return result
        def generation(lock):
            return {"runId":"123456","runAttempt":1,"pipelineHead":"a"*40,"artifactId":1,
                "artifactSha256":"b"*64,"receiptSha256":"c"*64,"generatedLockSha256":lock*64,"gitDiffSha256":"d"*64}
        prep1 = source("a", "b", lock=p.H3_ANCHOR["fileSha256"]["pnpm-lock.yaml"][0])
        prep1["fileSha256"]["pnpm-lock.yaml"] = p.H3_ANCHOR["fileSha256"]["pnpm-lock.yaml"]
        first = {"number":1,"parentSource":deepcopy(p.H3_ANCHOR),"preparation":prep1,
            "changedPaths":sorted(("package.json",p.LEDGER)),"contentSha256":{"package.json":"1"*64,p.LEDGER:"4"*64},
            "unchangedTreeSha256":"5"*64,"validation":None}
        h1 = source("c", "d", lock="6")
        first["validation"] = {"source":h1,"generation":generation("6"),"unchangedTreeSha256":"7"*64,"preparationAttempt":8}
        prep2 = source("2", "3", lock="6")
        second = {"number":2,"parentSource":h1,"preparation":prep2,"changedPaths":sorted((v.PRODUCER,p.LEDGER)),
            "contentSha256":{v.PRODUCER:"9"*64,p.LEDGER:"4"*64},"unchangedTreeSha256":"5"*64,"validation":None}
        h2 = source("6", "7", workspace="8", lock="9")
        record = {"schema":v.SCHEMA,"sourceGeneration":2,"workspaceSha256":"8"*64,
            "patchSha256":"b"*64,"proofSha256":"c"*64,"producerRuntimeSha256":"9"*64}
        second["validation"] = {"source":h2,"generation":generation("9"),"unchangedTreeSha256":"7"*64,"preparationAttempt":9,"vendorDerivation":record}
        family = {"schema":p.H3_FAMILY_SCHEMA,"publicAmendmentSha256":first["parentSource"] and __import__("bounded_run_contract_v109").H3_AMENDMENT_SHA256,
            "anchor":deepcopy(p.H3_ANCHOR),"generations":[first,second]}
        self.assertIs(p.validate_h3_family(family), family)
        for mutate in (lambda x: x["generations"][1]["validation"].pop("vendorDerivation"),
                lambda x: x["generations"][1]["validation"]["source"]["fileSha256"].update({"pnpm-workspace.yaml":"f"*64}),
                lambda x: x["generations"][0]["validation"].update(vendorDerivation=record)):
            broken=deepcopy(family);mutate(broken)
            with self.assertRaises(ValueError):p.validate_h3_family(broken)

    def test_actual_qualification_envelope_has_exact_safe_conclusions(self):
        record={"schema":v.SCHEMA,"sourceGeneration":2,"workspaceSha256":"a"*64,"patchSha256":"b"*64,"proofSha256":"c"*64,"producerRuntimeSha256":"d"*64}
        evidence=qualification_fixture(record)
        self.assertIs(v.validate_qualification(evidence,record,need),evidence)
        mutations=(lambda x:x["receipt"]["tests"].update(imageTested=True),
            lambda x:x["receipt"]["tests"]["cases"][-1].update(passed=False),
            lambda x:x["receipt"]["tests"]["cases"][-1].update(name="synthetic-case-0"),
            lambda x:x["receipt"]["testResultEvidence"].update(truncated=True),
            lambda x:x["controls"][1].update(caseCount=14),
            lambda x:x["controls"][0].update(timedOut=True))
        for mutate in mutations:
            bad=deepcopy(evidence);mutate(bad)
            bad["receiptSha256"]=v.digest(encoded(bad["receipt"]))
            with self.assertRaises(ValueError):v.validate_qualification(bad,record,need)

    def test_new_patched_install_precedes_controls_and_actual_package_once(self):
        record={"schema":v.SCHEMA,"sourceGeneration":2,"workspaceSha256":"a"*64,"patchSha256":"b"*64,"proofSha256":"c"*64,"producerRuntimeSha256":"d"*64}
        receipt=qualification_fixture(record)["receipt"]
        for timed_out in (False,True):
            with self.subTest(timed_out=timed_out),tempfile.TemporaryDirectory() as temporary:
                home=Path(temporary).resolve();source=home/"source";source.mkdir();calls=[]
                for name in [v.QUALIFIER]+[name for name,_ in v.CONTROL_TESTS]:
                    path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"fixed-source")
                def phase(argv,cwd,environment,context,operation,ordinal):
                    calls.append((argv,operation))
                    if operation=="vendor-controls":
                        target=Path(next(bit.split("=",1)[1] for bit in argv if bit.startswith("--test-reporter-destination=")))
                        count=v.CONTROL_TESTS[ordinal][1]
                        target.write_text("TAP version 13\n"+"".join("# %s %s\n"%(key,value) for key,value in (("tests",count),("pass",count),("fail",0),("cancelled",0),("skipped",0),("todo",0))))
                    if operation=="vendor-actual-qualification":Path(argv[-1]).write_bytes(encoded(receipt))
                    return SimpleNamespace(returncode=0,timed_out=timed_out if operation=="vendor-actual-qualification" else False,cleanup_settled=True)
                args=(source,record,{"original":home/"original.tgz","derived":home/"derived.tgz"},{"RUNNER_TEMP":str(home/"runner")},SimpleNamespace(phase_process=phase),{}, {"CI":"true"},home)
                if timed_out:
                    with patch.object(controller,"emit"),self.assertRaisesRegex(ValueError,"actual_qualification_failed"):controller.qualify_npm_vendor(*args)
                    self.assertEqual((home/"runner/v109-lock-diagnostic/vendor-qualification.raw").read_bytes(),encoded(receipt))
                else:
                    got=controller.qualify_npm_vendor(*args);self.assertEqual(got["receipt"],receipt)
                self.assertEqual([op for _,op in calls],["vendor-patched-install","vendor-controls","vendor-controls","vendor-actual-qualification"])
                self.assertEqual(calls[0][0],["pnpm","install","--frozen-lockfile","--ignore-scripts"])

    def test_failed_qualification_projects_only_fixed_observed_cause(self):
        value={"schema":"openclaw.npm-glob-vendor-qualification.v1","status":"failed","phase":"actual_package_tests",
            "reason":"qualification_failed","packageExecuted":False,"imageTested":False,"actualBunRuntimeTested":False,
            "exceptionCause":{"name":{"state":"recognized","value":"Error"},"code":{"state":"recognized","value":"ERR_MODULE_NOT_FOUND"}},
            "errorEvidence":{"bytes":100,"sha256":"a"*64}}
        projected=v.failed_qualification_projection(encoded(value),need)
        self.assertEqual(projected["exceptionCause"],value["exceptionCause"])
        self.assertEqual(projected["phase"],"actual_package_tests")
        self.assertFalse(projected["qualificationAccepted"])
        self.assertNotIn("errorEvidence",projected)
        self.assertEqual(projected["rawReceiptSha256"],v.digest(encoded(value)))

    def test_failed_cause_absent_unrecognized_and_unknowns_are_distinct(self):
        base={"schema":"openclaw.npm-glob-vendor-qualification.v1","status":"failed","phase":"proof",
            "reason":"qualification_failed","packageExecuted":False,"imageTested":False,"actualBunRuntimeTested":False}
        absent=v.failed_qualification_projection(encoded(base),need)
        self.assertFalse(absent["exceptionCausePresent"]);self.assertNotIn("exceptionCause",absent)
        value={**base,"exceptionCause":{"name":{"state":"absent"},"code":{"state":"unrecognized"}}}
        observed=v.failed_qualification_projection(encoded(value),need)
        self.assertTrue(observed["exceptionCausePresent"]);self.assertEqual(observed["exceptionCause"],value["exceptionCause"])
        for bad in ({"name":{"state":"recognized","value":"PrivateUnknown"},"code":{"state":"absent"}},
                {"name":{"state":"absent","value":"do-not-leak"},"code":{"state":"absent"}},
                {"name":{"state":"recognized","value":"Error"},"code":{"state":"recognized","value":"CUSTOM_PRIVATE_CODE"}}):
            with self.assertRaises(ValueError):v.failed_qualification_projection(encoded({**base,"exceptionCause":bad}),need)

    def test_unknown_failure_reason_never_repeats_unknown_text(self):
        value={"schema":"openclaw.npm-glob-vendor-qualification.v1","status":"failed","phase":"owned_staging",
            "reason":"unknown private path /synthetic/secret","packageExecuted":"unknown","imageTested":False,"actualBunRuntimeTested":False,
            "exceptionCause":{"name":{"state":"recognized","value":"TypeError"},"code":{"state":"absent"}}}
        result=v.failed_qualification_projection(encoded(value),need)
        self.assertEqual(result["reason"],{"state":"unrecognized"})
        self.assertNotIn("/synthetic/secret",json.dumps(result))
        for bad in ({**value,"status":"passed"},{**value,"phase":"private-unknown-phase"},{**value,"rawMessage":"private"}):
            with self.assertRaises(ValueError):v.failed_qualification_projection(encoded(bad),need)

    def test_failed_actual_import_cause_is_saved_and_emitted_before_same_refusal(self):
        record={"schema":v.SCHEMA,"sourceGeneration":2,"workspaceSha256":"a"*64,"patchSha256":"b"*64,"proofSha256":"c"*64,"producerRuntimeSha256":"d"*64}
        receipt={"schema":"openclaw.npm-glob-vendor-qualification.v1","status":"failed","phase":"actual_package_tests",
            "reason":"qualification_failed","packageExecuted":False,"imageTested":False,"actualBunRuntimeTested":False,
            "exceptionCause":{"name":{"state":"recognized","value":"Error"},"code":{"state":"recognized","value":"ENOENT"}}}
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary).resolve();source=home/"source";source.mkdir()
            for name in [v.QUALIFIER]+[name for name,_ in v.CONTROL_TESTS]:
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"fixed-source")
            def phase(argv,cwd,environment,context,operation,ordinal):
                if operation=="vendor-controls":
                    target=Path(next(bit.split("=",1)[1] for bit in argv if bit.startswith("--test-reporter-destination=")))
                    count=v.CONTROL_TESTS[ordinal][1]
                    target.write_text("TAP version 13\n"+"".join("# %s %s\n"%(key,value) for key,value in (("tests",count),("pass",count),("fail",0),("cancelled",0),("skipped",0),("todo",0))))
                if operation=="vendor-actual-qualification":Path(argv[-1]).write_bytes(encoded(receipt))
                return SimpleNamespace(returncode=1 if operation=="vendor-actual-qualification" else 0,timed_out=False,cleanup_settled=True)
            args=(source,record,{"original":home/"original.tgz","derived":home/"derived.tgz"},{"RUNNER_TEMP":str(home/"runner")},SimpleNamespace(phase_process=phase),{}, {"CI":"true"},home)
            with patch.object(controller,"emit") as output,self.assertRaisesRegex(ValueError,"actual_qualification_failed"):
                controller.qualify_npm_vendor(*args)
            diagnostic=p.parse((home/"runner/v109-lock-diagnostic/vendor-qualification.safe.json").read_bytes())
            self.assertEqual(diagnostic["exceptionCause"],receipt["exceptionCause"])
            self.assertEqual(output.call_args.args[0],diagnostic)
            self.assertFalse(diagnostic["qualificationAccepted"])
            self.assertEqual((home/"runner/v109-lock-diagnostic/vendor-qualification.raw").read_bytes(),encoded(receipt))
            self.assertFalse(any(path.name.startswith("npm-vendor-qualification-exception") for path in (home/"runner/v109-lock-diagnostic").iterdir()))

    def test_ci_host_guard_before_any_tool_or_archive(self):
        with patch.object(controller, "git_read", side_effect=AssertionError("no Git")), patch.object(controller, "vendor_archive", side_effect=AssertionError("no HTTP")):
            with self.assertRaisesRegex(ValueError, "native_ci_only"):
                controller.prepare_npm_vendor(Path("unused"), {}, {}, {}, SimpleNamespace(), {}, {}, Path("unused"))

    def test_bootstrap_and_producer_use_fixed_once_sequence_then_closed_writes(self):
        value, raw_patch, inventory = proof_fixture()
        package = b'{"dependencies":{"npm":"12.2.1"},"packageManager":"pnpm@12.15.0"}'
        workspace = b"minimumReleaseAge: 10080\npatchedDependencies:\n  zod@4.6.6: patches/zod.patch\n"
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve(); source = home/"source"; source.mkdir()
            for name, raw in (("package.json", package), (v.WORKSPACE, workspace), ("pnpm-lock.yaml", b"frozen-seed"), (v.PRODUCER, b"producer")):
                target = source/name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
            def git_read(_source, *args, **kwargs):
                if args[0] == "show":
                    return {"package.json": package, v.WORKSPACE: workspace, "pnpm-lock.yaml": b"frozen-seed", v.PATCH:raw_patch, v.PROOF:encoded(value)}[args[1].split(":", 1)[1]]
                if args[0] in ("diff", "ls-files"): return b""
                raise AssertionError(args)
            def phase(argv, cwd, environment, context, operation, ordinal):
                calls.append((argv, environment, operation))
                if operation == "vendor-derivation":
                    out = Path(argv[-1]); out.mkdir()
                    (out/Path(v.PATCH).name).write_bytes(raw_patch); (out/Path(v.PROOF).name).write_bytes(encoded(value))
                return SimpleNamespace(returncode=0, timed_out=False)
            bindings = {"sourceSuccessor": {"generations": [{"number": 2, "parentSource": {"sourceSha": "a" * 40}}]}}
            with patch.object(controller, "git_read", side_effect=git_read), patch.object(controller, "vendor_archive") as fetch, patch.object(v, "ORIGINAL_INVENTORY_SHA256", inventory):
                record, files, archives = controller.prepare_npm_vendor(source, bindings, {"source":{"sourceSha":"b"*40}}, {"GITHUB_ACTIONS":"true"}, SimpleNamespace(phase_process=phase), {"deadlineEpoch":9999999999}, {"PATH":"/known", "CI":"true"}, home)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0], ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"])
            self.assertEqual(calls[1][0][:3], ["node", v.PRODUCER, "--original-npm"])
            self.assertEqual(calls[1][1], {"PATH":"/known", "CI":"true", "GITHUB_ACTIONS":"true"})
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(set(files), set(v.GENERATED))
            self.assertEqual(set(archives), {"original", "derived"})
            self.assertEqual(record["workspaceSha256"], v.digest(v.expected_workspace(workspace, need)))
            self.assertNotIn("TOKEN", str(calls))
            # A related G3 that leaves vendor bytes unchanged still runs a
            # genuine producer and does not rewrite files to fabricate a delta.
            mtimes={name:(source/name).stat().st_mtime_ns for name in v.GENERATED}
            workspace=files[v.WORKSPACE]
            bindings["sourceSuccessor"]["generations"][-1]["number"]=3
            second_home=home/"second";second_home.mkdir()
            with patch.object(controller, "git_read", side_effect=git_read), patch.object(controller, "vendor_archive"), patch.object(v, "ORIGINAL_INVENTORY_SHA256", inventory):
                third, third_files, _ = controller.prepare_npm_vendor(source,bindings,{"source":{"sourceSha":"c"*40}}, {"GITHUB_ACTIONS":"true"},SimpleNamespace(phase_process=phase),{"deadlineEpoch":9999999999},{"PATH":"/known","CI":"true"},second_home)
            self.assertEqual(third["sourceGeneration"],3);self.assertEqual(third_files,files)
            self.assertEqual({name:(source/name).stat().st_mtime_ns for name in v.GENERATED},mtimes)

    def test_bootstrap_dependency_drift_refuses_before_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve(); (source/"package.json").write_bytes(b'{"dependencies":{"npm":"latest"}}')
            with patch.object(controller, "git_read", return_value=b'{"dependencies":{"npm":"12.2.1"}}'), patch.object(controller, "vendor_archive", side_effect=AssertionError("no HTTP")):
                with self.assertRaisesRegex(ValueError, "same_dependency_graph"):
                    controller.prepare_npm_vendor(source, {"sourceSuccessor":{"generations":[{"number":2,"parentSource":{"sourceSha":"a"*40}}]}}, {}, {"GITHUB_ACTIONS":"true"}, SimpleNamespace(), {"deadlineEpoch":9999999999}, {}, source)

    def test_private_capture_precedes_parse_and_keeps_oversize_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); report = root/"report"; report.write_bytes(b"{")
            raw = controller.capture_vendor_report(report, root/"capture", "malformed")
            with self.assertRaises(ValueError): p.parse(raw)
            self.assertEqual((root/"capture/malformed.raw").read_bytes(), b"{")
            report.write_bytes(b"x"*17)
            with self.assertRaisesRegex(ValueError, "evidence_incomplete"):
                controller.capture_vendor_report(report, root/"capture", "oversize", maximum=16)
            self.assertEqual((root/"capture/oversize.raw").read_bytes(), b"x"*16)
            metadata = p.parse((root/"capture/oversize.json").read_bytes())
            self.assertFalse(metadata["complete"]); self.assertEqual(metadata["reportedBytes"], 17)

    def test_registry_reads_are_fixed_capped_and_integrity_checked(self):
        raw = b"synthetic archive"; sha = v.digest(raw); sri = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()
        class Response:
            status = 200
            def __init__(self): self.raw = raw
            def geturl(self): return "https://registry.npmjs.org/npm/-/npm-12.2.1.tgz"
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, size): result, self.raw = self.raw[:size], self.raw[size:]; return result
        class Opener:
            def open(self, *args, **kwargs): return Response()
        with tempfile.TemporaryDirectory() as temporary, patch.object(controller.urllib.request, "build_opener", return_value=Opener()):
            out = Path(temporary).resolve()/"archive"
            controller.vendor_archive("https://registry.npmjs.org/npm/-/npm-12.2.1.tgz", sha, sri, out, {"deadlineEpoch":9999999999})
            self.assertEqual(out.read_bytes(), raw)
            with self.assertRaisesRegex(ValueError, "fixed_fresh"):
                controller.vendor_archive("https://registry.npmjs.org/npm/-/npm-12.2.1.tgz", sha, sri, out, {"deadlineEpoch":9999999999})
            with self.assertRaises(ValueError): controller.vendor_archive("https://example.invalid/arbitrary", sha, sri, out.with_name("other"), {"deadlineEpoch":9999999999})
            with self.assertRaises(ValueError): controller.vendor_archive("https://registry.npmjs.org/npm/-/npm-12.2.1.tgz", "f" * 64, sri, out.with_name("bad"), {"deadlineEpoch":9999999999})
            self.assertFalse(out.with_name("bad").exists())
            with self.assertRaises(ValueError): controller.core_no_redirect().redirect_request(None, None, 302, None, {}, "https://example.invalid")


if __name__ == "__main__": unittest.main()
