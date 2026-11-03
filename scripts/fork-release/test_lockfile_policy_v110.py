"""Pure operator-contract tests. No package resolver, imports or real HTTP.

V110_TEST_SOURCE names the already staged, reviewed candidate source for the
fixed source/patch-byte checks. Every graph and registry response below is a
synthetic fixture, never a claim that pnpm produced an accepted lock.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import unittest
import urllib.error

import lockfile_policy_v110 as policy


NOW = "2026-11-04T09:59:50Z"
OLD = "2026-10-01T00:00:00Z"
SRI = "sha512-" + base64.b64encode(b"a" * 64).decode()
OTHER_SRI = "sha512-" + base64.b64encode(b"b" * 64).decode()


def source_inputs():
    root = Path(os.environ["V110_TEST_SOURCE"])
    files = [root / "package.json", root / "ui/package.json", root / "tools/solid-lint/package.json"]
    for prefix in ("packages", "extensions", "examples"):
        files.extend(sorted((root / prefix).glob("*/package.json")))
    files.extend(root / name for name, _ in policy.PATCHES.values())
    files.append(root / "pnpm-workspace.yaml")
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in files}


# Independent expected consumer contract. It is deliberately not derived from
# FIXED_EDGES, so omitting a reviewed mail/claim parent in production is visible.
EDGES = {
    "@azure/identity@4.13.3": {"@azure/msal-node": "7.1.1"},
    "@microsoft/teams.apps@2.1.0": {"@azure/msal-node": "7.1.1"},
    "@azure/msal-node@7.1.1": {"@azure/msal-common": "16.14.3"},
    "@openclaw/crabline@0.1.29": {"re2js": "2.8.7"},
    "express@5.2.1": {"body-parser": "2.4.0"},
    "body-parser@2.4.0": {"qs": "6.16.1"},
    "mailauth@7.1.1": {"nodemailer": "10.1.4", "joi": "18.3.1"},
    "mailparser@3.9.36": {"nodemailer": "10.1.4"},
    "cacache@21.0.1": {"glob": "14.0.2"},
    "@a2ui/lit@0.12.0": {"zod": "4.6.6"},
    "@a2ui/web_core@0.12.0": {"zod": "4.6.6"},
    "@discord/embedded-app-sdk@2.5.0": {"zod": "4.6.6"},
    "make-fetch-happen@16.0.1": {"http-cache-semantics": "4.3.0"},
}


def graph():
    ids = set(EDGES) | set(policy.PATCHES) | {
        name + "@" + version for edges in EDGES.values() for name, version in edges.items()
    } | {"fast-uri@4.2.3", "follow-redirects@1.16.2", "minimatch@11.0.1",
         "undici@8.12.2", "npm@12.2.1", "vitest@5.0.5"}
    packages = {name: "  '" + name + "':\n    resolution: {integrity: " + SRI + "}" for name in ids}
    snapshots = {}
    for name in ids:
        key = name + ("(patch_hash=" + policy.PATCHES[name][1] + ")" if name in policy.PATCHES else "")
        lines = ["  '" + key + "':"]
        if name in EDGES:
            lines.append("    dependencies:")
            lines.extend("      '" + child + "': " + version for child, version in EDGES[name].items())
        snapshots[key] = "\n".join(lines)
    doc = "lockfileVersion: '9.0'\n\npatchedDependencies:\n" + "\n".join(
        "  '" + name + "': " + sha for name, (_, sha) in policy.PATCHES.items()) + "\n"
    return doc, {"packages": packages, "snapshots": snapshots}


def packument(name, versions):
    return json.dumps({"name": name,
        "versions": {v: {"name": name, "version": v, "dist": {"integrity": sri}}
                     for v, (sri, _) in versions.items()},
        "time": {v: date for v, (_, date) in versions.items()}}).encode()


def add_reviewed_browser(table):
    for name in ("@azure/msal-common@16.14.2", "@azure/msal-browser@5.24.0"):
        table["packages"][name] = "  '" + name + "':\n    resolution: {integrity: " + SRI + "}"
    table["snapshots"]["@azure/msal-common@16.14.2"] = "  '@azure/msal-common@16.14.2': {}"
    table["snapshots"]["@azure/msal-browser@5.24.0"] = "  '@azure/msal-browser@5.24.0':\n    dependencies:\n      '@azure/msal-common': 16.14.2"


def summary(browser=False):
    doc, table = graph()
    if browser:
        add_reviewed_browser(table)
    critical = policy.verify_security(doc, table)
    selected = {("@openclaw/fs-safe", "0.26.5"): SRI, ("fixture", "1.0.0"): SRI}
    age = policy.verify_age_and_integrity(selected,
        lambda name: packument(name, {"0.26.5" if name.startswith("@") else "1.0.0": (SRI, OLD)}), NOW)
    return {"schema": "openclaw.v110.generated-lock-security.v1", "beforeLockSha256": "a" * 64,
            "generatedLockSha256": "b" * 64, "workspaceImporters": 2,
            "criticalVersionSets": critical, "msalCommonConsumers": policy.msal_common_consumers(table),
            "patchesSha256": policy.digest(policy.canonical(
                {name: sha for name, (_, sha) in policy.PATCHES.items()})), "closureAge": age,
            "allSelectedRegistryIntegritiesMatched": True, "nativeAdvisoryAuditsStillRequired": True,
            "exactGeneratedDiffReviewRequiredBeforeCommit": True,
            "unrelatedGeneratedDiffAutomaticallyApproved": False, "qualified": False,
            "imageBuilt": False, "productionAuthorized": False}


class SourceAndGraphTests(unittest.TestCase):
    def test_actual_reviewed_source_and_patch_bytes(self):
        manifests = policy.validate_source_inputs(source_inputs(), NOW)
        self.assertEqual(manifests["."]["dependencies"]["npm"], "12.2.1")
        self.assertEqual(manifests["."]["dependencies"]["@modelcontextprotocol/sdk"], "1.32.1")
        self.assertGreater(len(manifests), 100)

    def test_source_clock_and_exact_hashes_refuse_drift(self):
        inputs = source_inputs()
        for at in ("2026-11-04T09:59:49Z", "2026-11-06T03:14:21Z"):
            with self.subTest(at=at), self.assertRaisesRegex(policy.LockRefusal, "package_use_clock"):
                policy.validate_source_inputs(inputs, at)
        for path in ("pnpm-workspace.yaml", "package.json", "patches/vitest@5.0.5.patch"):
            changed = dict(inputs)
            changed[path] += b"\n"
            with self.subTest(path=path), self.assertRaisesRegex(policy.LockRefusal, "reviewed_"):
                policy.validate_source_inputs(changed, NOW)

    def test_official_seed_lock_is_not_combined_source_evidence(self):
        inputs = source_inputs()
        seed = (Path(os.environ["V110_TEST_SOURCE"]) / "pnpm-lock.yaml").read_bytes()
        def forbidden(_):
            self.fail("Registry must not be queried before source override refusal")
        with self.assertRaisesRegex(policy.LockRefusal, "source_overrides_preserved"):
            policy.verify_generated_lock(seed, seed, inputs, forbidden, NOW)

    def test_fixed_security_edges_and_patch_registration_accept(self):
        doc, table = graph()
        result = policy.verify_security(doc, table)
        self.assertEqual(result["zod"], ["4.6.6"])
        self.assertEqual(result["@azure/msal-common"], ["16.14.3"])
        self.assertEqual(result["minimatch"], ["11.0.1"])

    def test_new_secure_zod_transitive_is_not_silently_downgraded(self):
        doc, table = graph()
        table["packages"]["zod@4.6.7"] = "  zod@4.6.7:\n    resolution: {integrity: " + SRI + "}"
        table["snapshots"]["zod@4.6.7"] = "  zod@4.6.7: {}"
        self.assertEqual(policy.verify_security(doc, table)["zod"], ["4.6.6", "4.6.7"])

    def test_legacy_zod_and_global_matcher_downgrade_refuse(self):
        for key in ("zod@3.25.76", "minimatch@10.2.6"):
            doc, table = graph()
            table["packages"][key] = "  '" + key + "': {}"
            with self.subTest(key=key), self.assertRaises(policy.LockRefusal):
                policy.verify_security(doc, table)

    def test_current_mailauth_joi_edge_is_required(self):
        doc, table = graph()
        table["snapshots"]["mailauth@7.1.1"] = table["snapshots"]["mailauth@7.1.1"].replace("joi': 18.3.1", "joi': 18.2.9")
        table["packages"]["joi@18.2.9"] = "  joi@18.2.9: {}"
        with self.assertRaisesRegex(policy.LockRefusal, "exact_security_parent_edge"):
            policy.verify_security(doc, table)

    def test_wrong_patch_encoding_and_unpatched_snapshot_refuse(self):
        doc, table = graph()
        old = "c7225d77fb8a242bd88070b9787737119caea3ba29fdccb38419b9fe4c196e92"
        with self.assertRaisesRegex(policy.LockRefusal, "exact_patch_registration"):
            policy.verify_security(doc.replace(old, "a" * 64), table)
        zod = next(key for key in table["snapshots"] if key.startswith("zod@"))
        table["snapshots"]["zod@4.6.6"] = table["snapshots"].pop(zod)
        with self.assertRaisesRegex(policy.LockRefusal, "exact_patch_snapshot"):
            policy.verify_security(doc, table)

    def test_old_msal_common_is_limited_to_reviewed_browser(self):
        doc, table = graph()
        add_reviewed_browser(table)
        policy.verify_security(doc, table)
        self.assertEqual(policy.msal_common_consumers(table), {
            "@azure/msal-node@7.1.1": "16.14.3", "@azure/msal-browser@5.24.0": "16.14.2"})
        table["packages"]["unexpected-parent@1.0.0"] = "  unexpected-parent@1.0.0: {}"
        table["snapshots"]["unexpected-parent@1.0.0"] = "  unexpected-parent@1.0.0:\n    dependencies:\n      '@azure/msal-common': 16.14.2"
        with self.assertRaisesRegex(policy.LockRefusal, "reviewed_msal_common_consumers"):
            policy.verify_security(doc, table)

    def test_msal_versions_are_closed_not_only_required_members(self):
        for name in ("@azure/msal-node@7.1.0", "@azure/msal-common@16.14.1",
                     "@azure/msal-common@16.14.2"):
            doc, table = graph()
            table["packages"][name] = "  '" + name + "': {}"
            table["snapshots"][name] = "  '" + name + "': {}"
            with self.subTest(name=name), self.assertRaisesRegex(policy.LockRefusal, "closed_msal_selected_versions"):
                policy.verify_security(doc, table)

    def test_msal_unreviewed_current_consumer_and_alias_refuse(self):
        for edge in ("'@azure/msal-common': 16.14.3",
                     "'common-alias': npm:@azure/msal-common@16.14.3"):
            doc, table = graph()
            table["packages"]["unexpected-parent@1.0.0"] = "  unexpected-parent@1.0.0: {}"
            table["snapshots"]["unexpected-parent@1.0.0"] = "  unexpected-parent@1.0.0:\n    dependencies:\n      " + edge
            with self.subTest(edge=edge), self.assertRaisesRegex(policy.LockRefusal, "reviewed_msal_common_consumers"):
                policy.verify_security(doc, table)

    def test_browser_exception_needs_positive_package_and_exact_named_edge(self):
        doc, original = graph()
        add_reviewed_browser(original)
        changes = [lambda table: table["packages"].pop("@azure/msal-browser@5.24.0"),
                   lambda table: table["snapshots"].pop("@azure/msal-browser@5.24.0"),
                   lambda table: table["snapshots"].__setitem__("@azure/msal-browser@5.24.0",
                       "  '@azure/msal-browser@5.24.0':\n    dependencies:\n      'common-alias': npm:@azure/msal-common@16.14.2")]
        for change in changes:
            table = deepcopy(original); change(table)
            with self.subTest(change=change), self.assertRaises(policy.LockRefusal):
                policy.verify_security(doc, table)

    def test_importer_exact_version_and_workspace_link_are_bound(self):
        doc = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      npm:\n        specifier: 12.2.1\n        version: 12.2.1\n      '@fixture/local':\n        specifier: workspace:*\n        version: link:packages/local\n\n  packages/local: {}\n"
        manifests = {".": {"dependencies": {"npm": "12.2.1", "@fixture/local": "workspace:*"}},
                     "packages/local": {"name": "@fixture/local"}}
        packages = {"npm@12.2.1": "", "npm@12.2.0": ""}
        self.assertEqual(policy.check_importers(doc, manifests, {}, packages), 2)
        for old, new in (("version: 12.2.1", "version: 12.2.0"), ("link:packages/local", "link:../private")):
            with self.subTest(new=new), self.assertRaises(policy.LockRefusal):
                policy.check_importers(doc.replace(old, new), manifests, {}, packages)

    def test_missing_importer_duplicate_field_or_undeclared_dependency_refuse(self):
        doc = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      npm:\n        specifier: 12.2.1\n        version: 12.2.1\n"
        for bad, manifests in ((doc, {".": {"dependencies": {}}}),
                               (doc, {".": {"dependencies": {"npm": "12.2.1"}}, "ui": {}}),
                               (doc.replace("version: 12.2.1", "version: 12.2.1\n        version: 12.2.1"),
                                {".": {"dependencies": {"npm": "12.2.1"}}})):
            with self.subTest(bad=bad), self.assertRaises(policy.LockRefusal):
                policy.check_importers(bad, manifests, {}, {"npm@12.2.1": ""})

    def test_selected_package_integrity_and_snapshot_membership(self):
        table = {"packages": {"fixture@1.0.0": "  fixture@1.0.0:\n    resolution: {integrity: " + SRI + "}"},
                 "snapshots": {"fixture@1.0.0(peer@1.0.0)": ""}}
        self.assertEqual(policy.selected_packages([table]), {("fixture", "1.0.0"): SRI})
        for changed in (dict(table, snapshots={}), dict(table, packages={"fixture@1.0.0": "  fixture@1.0.0: {}"})):
            with self.subTest(changed=changed), self.assertRaises(policy.LockRefusal):
                policy.selected_packages([changed])
        conflicting = deepcopy(table)
        conflicting["packages"]["fixture@1.0.0"] = conflicting["packages"]["fixture@1.0.0"].replace(SRI, OTHER_SRI)
        with self.assertRaisesRegex(policy.LockRefusal, "conflicting_registry_integrity"):
            policy.selected_packages([table, conflicting])

    def test_snapshot_metadata_ends_edge_scope_and_duplicates_refuse(self):
        chunk = "  fixture@1.0.0:\n    dependencies:\n      child: 1.0.0\n    optional: true\n    transitivePeerDependencies:\n      - other\n"
        self.assertEqual(policy.snapshot_edges(chunk), {"child": ("child", "1.0.0")})
        for extra in ("    dependencies:\n      child: 2.0.0\n", "    optional: false\n"):
            with self.subTest(extra=extra), self.assertRaisesRegex(policy.LockRefusal, "duplicate_field"):
                policy.snapshot_edges(chunk + extra)


class AgeAndReceiptTests(unittest.TestCase):
    def test_empty_or_invalid_selected_input_never_queries_registry(self):
        def forbidden(_):
            self.fail("No registry request for invalid selected tuple")
        for selected in ({}, {("https://private.invalid", "1.0.0"): SRI},
                         {("fixture", "1.0.0"): None}):
            with self.subTest(selected=selected), self.assertRaises(policy.LockRefusal):
                policy.verify_age_and_integrity(selected, forbidden, NOW)

    def test_every_selected_tuple_including_wildcard_exclusion_is_checked(self):
        selected = {("@openai/codex", "0.164.0"): SRI,
                    ("fixture", "1.0.0"): SRI, ("fixture", "2.0.0"): OTHER_SRI}
        calls = []
        def lookup(name):
            calls.append(name)
            return packument(name, {"0.164.0": (SRI, OLD)}) if name.startswith("@") else packument(
                name, {"1.0.0": (SRI, OLD), "2.0.0": (OTHER_SRI, "2026-10-28T09:59:49.641Z")})
        result = policy.verify_age_and_integrity(selected, lookup, NOW)
        self.assertEqual(calls, ["@openai/codex", "fixture"])
        self.assertEqual(result["checkedTupleCount"], 3)
        self.assertEqual(result["unknownTupleCount"], 0)
        self.assertEqual(result["maximumEligibleAt"], "2026-11-04T09:59:50Z")
        self.assertTrue(result["allSelectedExclusionsAlsoChecked"])

    def test_underage_exclusion_future_and_missing_timestamp_refuse(self):
        for published in ("2026-10-28T09:59:50.001Z", "2026-11-05T00:00:00Z", None):
            raw = packument("@openai/codex", {"0.164.0": (SRI, published)})
            with self.subTest(published=published), self.assertRaises(policy.LockRefusal):
                policy.verify_age_and_integrity({("@openai/codex", "0.164.0"): SRI}, lambda _: raw, NOW)

    def test_wrong_registry_identity_version_integrity_or_duplicate_refuses(self):
        valid = packument("fixture", {"1.0.0": (SRI, OLD)})
        variants = [valid.replace(b'"name": "fixture"', b'"name": "other"', 1),
                    valid.replace(SRI.encode(), OTHER_SRI.encode()),
                    valid.replace(b'"1.0.0": {', b'"2.0.0": {'),
                    valid.replace(b'{"name":', b'{"name":"duplicate","name":', 1),
                    b'{"name":NaN}']
        for raw in variants:
            with self.subTest(raw=raw[:50]), self.assertRaises(policy.LockRefusal):
                policy.verify_age_and_integrity({("fixture", "1.0.0"): SRI}, lambda _: raw, NOW)

    def test_summary_accepts_complete_unqualified_producer_output(self):
        result = summary()
        self.assertIs(policy.validate_generated_summary(result, "a" * 64, "b" * 64, NOW), result)

    def test_summary_accepts_only_positively_bound_browser_exception(self):
        result = summary(browser=True)
        self.assertEqual(result["criticalVersionSets"]["@azure/msal-common"], ["16.14.2", "16.14.3"])
        self.assertIs(policy.validate_generated_summary(result, "a" * 64, "b" * 64, NOW), result)
        variants = [summary(browser=True) for _ in range(4)]
        del variants[0]["msalCommonConsumers"]["@azure/msal-browser@5.24.0"]
        variants[1]["msalCommonConsumers"]["@azure/msal-browser@5.24.0"] = "16.14.3"
        variants[2]["msalCommonConsumers"]["unexpected-parent@1.0.0"] = "16.14.2"
        variants[3]["criticalVersionSets"]["@azure/msal-common"] = ["16.14.3"]
        for index, result in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(policy.LockRefusal):
                policy.validate_generated_summary(result, "a" * 64, "b" * 64, NOW)

    def test_summary_refuses_extra_msal_versions_or_unreviewed_consumer(self):
        for name, version in (("@azure/msal-node", "7.1.0"), ("@azure/msal-common", "16.14.1"),
                              ("@azure/msal-common", "16.14.2")):
            result = summary()
            result["criticalVersionSets"][name] = sorted(result["criticalVersionSets"][name] + [version])
            with self.subTest(name=name, version=version), self.assertRaisesRegex(policy.LockRefusal, "closed_msal_selected_versions"):
                policy.validate_generated_summary(result, "a" * 64, "b" * 64, NOW)
        result = summary()
        result["msalCommonConsumers"]["unexpected-parent@1.0.0"] = "16.14.3"
        with self.assertRaisesRegex(policy.LockRefusal, "reviewed_msal_common_consumers"):
            policy.validate_generated_summary(result, "a" * 64, "b" * 64, NOW)

    def test_summary_refuses_boolean_counts_unknown_missing_hash_or_qualification(self):
        changes = [("workspaceImporters", True), ("generatedLockSha256", "c" * 64),
                   ("qualified", True), ("nativeAdvisoryAuditsStillRequired", False)]
        for key, value in changes:
            row = summary(); row[key] = value
            with self.subTest(key=key), self.assertRaises(policy.LockRefusal):
                policy.validate_generated_summary(row, "a" * 64, "b" * 64, NOW)
        for key, value in (("unknownTupleCount", 1), ("checkedTupleCount", 1),
                           ("selectedTupleCount", True), ("maximumEligibleAt", "2026-11-05T00:00:00Z")):
            row = summary(); row["closureAge"][key] = value
            with self.subTest(key=key), self.assertRaises(policy.LockRefusal):
                policy.validate_generated_summary(row, "a" * 64, "b" * 64, NOW)
        row = summary(); del row["closureAge"]["tuplesSha256"]
        with self.assertRaises(policy.LockRefusal):
            policy.validate_generated_summary(row, "a" * 64, "b" * 64, NOW)


class Response(io.BytesIO):
    status = 200
    def __init__(self, raw, url):
        super().__init__(raw)
        self.url = url
        self.headers = Message(); self.headers["Content-Type"] = "application/json"
    def geturl(self):
        return self.url


class Opener:
    def __init__(self, raw=b"{}", other_url=None, error=None):
        self.raw, self.other_url, self.error, self.calls = raw, other_url, error, []
    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error:
            raise self.error
        return Response(self.raw, self.other_url or request.full_url)


class RegistryTransportTests(unittest.TestCase):
    def test_fixed_scoped_route_has_no_credentials_and_bounded_timeout(self):
        opener = Opener()
        client = policy.PublicRegistry(100, opener=opener, clock=lambda: 90)
        self.assertEqual(client("@scope/pkg"), b"{}")
        request, timeout = opener.calls[0]
        self.assertEqual(request.full_url, "https://registry.npmjs.org/%40scope%2Fpkg")
        self.assertFalse(any(key.lower() in ("authorization", "cookie", "proxy-authorization") for key in request.headers))
        self.assertEqual(timeout, 10)

    def test_unsafe_names_repeated_lookup_deadline_and_response_caps_refuse(self):
        for name in ("../private", "fixture?token=x", "https://other.invalid", ".", "@scope/../pkg"):
            opener = Opener(); client = policy.PublicRegistry(100, opener=opener, clock=lambda: 90)
            with self.subTest(name=name), self.assertRaises(policy.LockRefusal):
                client(name)
            self.assertEqual(opener.calls, [])
        opener = Opener(); client = policy.PublicRegistry(100, opener=opener, clock=lambda: 90)
        client("fixture")
        with self.assertRaisesRegex(policy.LockRefusal, "request_count"):
            client("fixture")
        client = policy.PublicRegistry(90, opener=opener, clock=lambda: 90)
        with self.assertRaisesRegex(policy.LockRefusal, "deadline"):
            client("other")
        client = policy.PublicRegistry(100, opener=Opener(b"0123456789"), clock=lambda: 90)
        client.MAX_BODY = 8
        with self.assertRaisesRegex(policy.LockRefusal, "response_cap"):
            client("fixture")

    def test_redirect_and_http_failure_do_not_expose_response_body(self):
        client = policy.PublicRegistry(100, opener=Opener(other_url="https://private.invalid"), clock=lambda: 90)
        with self.assertRaisesRegex(policy.LockRefusal, "registry_route"):
            client("fixture")
        error = urllib.error.HTTPError("https://registry.npmjs.org/fixture", 403, "private canary", {}, io.BytesIO(b"private canary"))
        client = policy.PublicRegistry(100, opener=Opener(error=error), clock=lambda: 90)
        with self.assertRaises(policy.LockRefusal) as captured:
            client("fixture")
        self.assertEqual(captured.exception.evidence, {"name": "fixture", "status": 403})
        self.assertNotIn("private canary", str(captured.exception))


if __name__ == "__main__":
    unittest.main()
