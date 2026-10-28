"""10.8 contracts tested on real, tiny Git graphs without running product code."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import preflight
import release
from test_merge_source import MergeFixture, encoded, git

LEDGER = "custom-patches/reconciliation-2026.10.8.json"
NOTE = "custom-patches/NEXT-RELEASE-2026.10.8.md"
MANIFEST = "custom-patches/manifest.json"
DOCS = ("docs/plugins/sdk-runtime.md", "docs/plugins/sdk-runtime/config-and-utilities.md")
ROUTES = ("test/vitest/vitest.database-worker-core-paths.mjs", "test/vitest/vitest.gateway-server-paths.mjs")
RUNTIME = "src/plugins/loader-module-runtime.ts"
WORKBOARD = "extensions/workboard/src/producer.ts"
SECURITY = "test/native-security.test.mjs"
PACKAGES = ("package.json", "extensions/workboard/package.json")
UI_PACKAGE = "ui/package.json"
WORKSPACE = "pnpm-workspace.yaml"
OLD_PATCH, NEW_PATCH = release.V108_OLD_PATCH, release.V108_NEW_PATCH
REPAIR_TESTS = tuple(sorted(release.V108_REMEDIATION_PATHS - {
    *PACKAGES, UI_PACKAGE, WORKSPACE, "pnpm-lock.yaml", OLD_PATCH, NEW_PATCH,
    "test/v108-remediation-security.test.mjs"}))
WORKSPACE_BEFORE = ('minimumReleaseAgeStrict: true\noverrides:\n  fast-uri: 4.2.1\n'
                    '  ip-address: 10.7.3\n  "mailauth@7.1.0>nodemailer": 10.0.13\n'
                    '  qs: 6.16.0\npatchedDependencies:\n'
                    '  vitest@5.0.1: patches/vitest@5.0.1.patch\n')
WORKSPACE_AFTER = ('minimumReleaseAgeStrict: true\noverrides:\n  fast-uri: 4.2.3\n'
                  '  ip-address: 10.7.4\n  "mailauth@7.1.0>nodemailer": 10.1.4\n'
                  '  "mailparser@3.9.33>nodemailer": 10.1.4\n'
                  '  "mermaid@12.1.0>katex": 0.18.2\n'
                  '  qs: 6.16.1\npatchedDependencies:\n'
                  '  vitest@5.0.5: patches/vitest@5.0.5.patch\n')


class V108Fixture(MergeFixture):
    def __init__(self, root):
        self.root = root
        git(root, "init", "-q")
        git(root, "config", "user.email", "merge-test@example.invalid")
        git(root, "config", "user.name", "Merge Test")
        self.write("src/a.test.ts", "synthetic gate a\n")
        self.write("src/b.test.ts", "synthetic gate b\n")
        for name in PACKAGES:
            self.write(name, encoded(self.package("2026.10.7", "1.0.0")))
        self.write(UI_PACKAGE, encoded({"devDependencies": {
            "vitest": "5.0.1", "@vitest/browser-playwright": "5.0.1", "@vitest/browser": "5.0.1"}}))
        self.write(WORKSPACE, WORKSPACE_BEFORE)
        self.write("pnpm-lock.yaml", "original multi-document lock\n")
        for name in (*DOCS, *ROUTES, RUNTIME, WORKBOARD, SECURITY, *REPAIR_TESTS):
            self.write(name, "common fixture\n")
        self.common = self.commit("common 10.7")
        for name in (*DOCS, *ROUTES, RUNTIME, WORKBOARD, SECURITY, *REPAIR_TESTS):
            self.write(name, "reviewed fork behavior\n")
        self.write(OLD_PATCH, "reviewed Vitest worker patch\n")
        for name in PACKAGES:
            self.write(name, encoded(self.package("2026.10.7", "2.0.0")))
        self.write(MANIFEST, encoded({"sourceOnly": "10.7"}))
        self.fork = self.commit("reviewed fork 10.7")
        git(root, "checkout", "-q", "--detach", self.common)
        self.write("historical-security.txt", "historical approved input\n")
        self.security = self.commit("historical security input")
        git(root, "checkout", "-q", "--detach", self.common)
        for name in PACKAGES:
            self.write(name, encoded(self.package("2026.10.8", "1.0.0")))
        for name in (*DOCS, *ROUTES, RUNTIME):
            self.write(name, "10.8 upstream behavior\n")
        self.write("upstream-only.txt", "10.8 upstream addition\n")
        self.upstream = self.commit("official upstream 10.8")
        git(root, "checkout", "-q", "--detach", self.fork)
        for name in PACKAGES:
            self.write(name, encoded(self.package("2026.10.8", "2.0.0")))
        self.write(MANIFEST, encoded({"sourceOnly": "10.8"}))
        for name in (*DOCS, *ROUTES, RUNTIME):
            self.write(name, "10.8 upstream plus reviewed fork behavior\n")
        self.write("upstream-only.txt", "10.8 upstream addition\n")
        self.write(NOTE, "source only; runtime unqualified\n")
        git(root, "add", ".")
        tree = git(root, "write-tree")
        fork_paths = set(git(root, "diff", "--name-only", self.common, self.fork).splitlines())
        result_paths = set(git(root, "diff", "--name-only", self.upstream, tree).splitlines())
        rows = []
        for name in sorted(fork_paths | result_paths):
            disposition = "CARRIED_EXACT"
            if name in DOCS:
                disposition = "MERGED_SDK_CONTRACT_DOCUMENTATION"
            elif name in ROUTES:
                disposition = "MERGED_MAINTAINED_TEST_ROUTE_UNION"
            elif name == RUNTIME:
                disposition = "MERGED_TASK_ACCESS_AND_IMMUTABLE_INSPECTION"
            elif name in PACKAGES:
                disposition = "MERGED_UPSTREAM_METADATA_AND_FORK_SECURITY"
            elif name == NOTE:
                disposition = "ADDED_SOURCE_ONLY_RUNBOOK"
            elif name == MANIFEST:
                disposition = "ADAPTED_SOURCE_ONLY_RELEASE_BINDING"
            rows.append({"path": name, "upstream107": self.entry(self.common, name),
                         "fork107": self.entry(self.fork, name), "upstream108": self.entry(self.upstream, name),
                         "result": self.entry(tree, name), "disposition": disposition})
        self.ledger = {"schema": "openclaw-v108-source-reconciliation-v1", "upstream107": self.common,
                       "fork107Source": self.fork, "upstream108": self.upstream,
                       "priorForkDeltaPaths": len(fork_paths), "textualConflicts": 0,
                       "qualificationTransferred": False,
                       "selfExclusion": {"path": LEDGER, "reason": "result-blob self-reference excluded"}, "paths": rows}
        self.write(LEDGER, encoded(self.ledger))
        git(root, "add", ".")
        self.integration = self.commit_tree(git(root, "write-tree"), [self.fork, self.upstream])
        git(root, "checkout", "-q", "--detach", self.integration)
        self.source108 = {"baseCommit": self.upstream, "baseTree": self.tree(self.upstream),
                          "patches": [self.identity(self.integration)], **self.identity(self.integration), "merge": {
                              "schema": "openclaw.fork-source-merge.v3", "commonCommit": self.common,
                              "commonTree": self.tree(self.common), "forkCommit": self.fork,
                              "forkTree": self.tree(self.fork), "integration": self.identity(self.integration),
                              "successors": [], "securitySource": self.identity(self.security),
                              "reconciliation": self.proof(self.integration)}}
        self.manifest108 = {"schema": "openclaw.fork-release.v1", "repository": "fr-meyer/openclaw",
                            "candidate": "v2026.10.8-fixture", "productionEligible": False, "source": self.source108,
                            "gates": {"patchLifecycle": ["src/a.test.ts"], "producerConsumer": ["src/b.test.ts"]},
                            "image": {"architecture": "amd64", "extensions": "codex,workboard"}}
        self.tag108 = self.tag_object(self.upstream)

    @staticmethod
    def package(version, dependency):
        return {"name": "synthetic", "version": version, "dependencies": {"security-parent": dependency},
                "devDependencies": {"vitest": "5.0.1", "@vitest/browser-playwright": "5.0.1", "@vitest/coverage-v8": "5.0.1"},
                "pnpm": {"overrides": {"security-child": dependency}}, "scripts": {"check": "synthetic"},
                "peerDependencies": {"openclaw": ">=" + version},
                "openclaw": {"compat": {"pluginApi": ">=" + version}, "build": {"openclawVersion": version}}}

    def entry(self, commit, path):
        item = git(self.root, "ls-tree", commit, "--", path)
        return {"mode": item.split()[0], "blob": item.split()[2]} if item else None

    def identity(self, commit):
        return {"commit": commit, "tree": self.tree(commit)}

    def proof(self, commit):
        raw = subprocess.check_output(["git", "-C", str(self.root), "show", commit + ":" + LEDGER])
        return {"path": LEDGER, "blob": self.blob(commit, LEDGER), "sha256": hashlib.sha256(raw).hexdigest()}

    def tag_object(self, target, name="v2026.10.8"):
        return git(self.root, "hash-object", "-w", "-t", "tag", "--stdin", data=(
            f"object {target}\ntype commit\ntag {name}\n"
            "tagger Merge Test <merge-test@example.invalid> 1700000000 +0000\n\nSynthetic release\n"))

    def replaced_source(self, ledger=None, writes=None, removals=(), modes=(), parents=None):
        git(self.root, "reset", "--hard", self.integration)
        git(self.root, "clean", "-fdq")
        for name, content in (writes or {}).items():
            self.write(name, content)
        for name in removals:
            (self.root / name).unlink()
        for name in modes:
            (self.root / name).chmod(0o755)
        if ledger is not None:
            self.write(LEDGER, encoded(ledger))
        git(self.root, "add", ".")
        commit = self.commit_tree(git(self.root, "write-tree"), parents or [self.fork, self.upstream])
        source = copy.deepcopy(self.source108)
        source.update(**self.identity(commit), patches=[self.identity(commit)])
        source["merge"].update(integration=self.identity(commit), reconciliation=self.proof(commit))
        return source

    def successor_source(self, count):
        source = copy.deepcopy(self.source108)
        parent = self.integration
        for _ in range(count):
            parent = self.commit_tree(self.tree(parent), [parent])
            source["merge"]["successors"].append(self.identity(parent))
        source.update(**self.identity(parent), patches=[self.identity(parent)])
        return source

    def remediation_source(self, writes=None, removals=(), mutate_ledger=None, modes=()):
        git(self.root, "reset", "--hard", self.integration)
        git(self.root, "clean", "-fdq")
        for name, content in (writes or {}).items():
            self.write(name, content)
        for name in removals:
            (self.root / name).unlink()
        for name in modes:
            (self.root / name).chmod(0o755)
        git(self.root, "add", ".")
        tree = git(self.root, "write-tree")
        changed = set(git(self.root, "diff", "--name-only", self.integration, tree).splitlines())
        rows = {item["path"]: copy.deepcopy(item) for item in self.ledger["paths"]}
        for name in changed - {LEDGER}:
            rows[name] = {"path": name, "upstream107": self.entry(self.common, name),
                          "fork107": self.entry(self.fork, name), "upstream108": self.entry(self.upstream, name),
                          "result": self.entry(tree, name), "disposition": (
                              release.V108_PATCH_RETIREMENT if name == OLD_PATCH else release.V108_REMEDIATION)}
        ledger = {**copy.deepcopy(self.ledger), "paths": [rows[name] for name in sorted(rows)]}
        if mutate_ledger:
            mutate_ledger(ledger)
        self.write(LEDGER, encoded(ledger))
        git(self.root, "add", ".")
        commit = self.commit_tree(git(self.root, "write-tree"), [self.integration])
        source = copy.deepcopy(self.source108)
        source.update(**self.identity(commit), patches=[self.identity(commit)])
        source["merge"].update(successors=[self.identity(commit)], reconciliation=self.proof(commit))
        return source


class V108MergeSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.fixture = V108Fixture(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def refused(self, source, reason=None):
        with self.assertRaisesRegex(release.Refusal, reason or ".*"):
            release.check_source_graph(source, self.fixture.root)

    def changed_ledger_refused(self, mutate, reason=None, **changes):
        ledger = copy.deepcopy(self.fixture.ledger)
        mutate(ledger)
        self.refused(self.fixture.replaced_source(ledger=ledger, **changes), reason)

    def test_exact_source_manifest_and_bounded_successors_pass(self):
        f = self.fixture
        git(f.root, "reset", "--hard", f.integration)
        path = f.root / "manifest-fixture.json"
        path.write_bytes(encoded(f.manifest108))
        manifest, _ = release.manifest_at(path)
        release.check_source(manifest, f.root)
        self.assertEqual(release.validation_node_version({"upstream": {"tag": "v2026.10.8"}}), "24.22.1")
        for count in (1, 16):
            release.check_source_graph(f.successor_source(count), f.root)
        self.refused(f.successor_source(17), "successor count")

    def package_repair(self, name):
        document = json.loads(git(self.fixture.root, "show", self.fixture.integration + ":" + name))
        for key in ("vitest", "@vitest/browser-playwright", "@vitest/coverage-v8"
                    if name == "package.json" else "@vitest/browser"):
            document["devDependencies"][key] = "5.0.5"
        return document

    def test_complete_finite_successor_repairs_pass_without_relabeling_history(self):
        f = self.fixture
        writes = {name: "narrow synthetic fixture correction\n" for name in REPAIR_TESTS}
        writes.update({"package.json": encoded(self.package_repair("package.json")),
                       UI_PACKAGE: encoded(self.package_repair(UI_PACKAGE)), WORKSPACE: WORKSPACE_AFTER,
                       "pnpm-lock.yaml": "regenerated multi-document lock\n",
                       NEW_PATCH: "rebased Vitest worker patch\n",
                       "test/v108-remediation-security.test.mjs": "synthetic parent compatibility test\n"})
        source = f.remediation_source(writes=writes, removals=(OLD_PATCH,))
        release.check_source_graph(source, f.root)
        self.assertEqual(json.loads(git(f.root, "show", f.integration + ":" + LEDGER)), f.ledger)

    def test_new_remediation_test_requires_exact_ledger_coverage(self):
        f = self.fixture
        name = "test/v108-remediation-security.test.mjs"
        source = f.remediation_source(writes={name: "synthetic new test\n"})
        release.check_source_graph(source, f.root)
        self.refused(f.remediation_source(writes={name: "synthetic new test\n"},
                     mutate_ledger=lambda x: x.update(paths=[r for r in x["paths"] if r["path"] != name])),
                     "coverage")

    def test_approved_fixture_generator_successor_paths_pass_complete_graph(self):
        f = self.fixture
        writes = {
            "src/agents/subagents/registry/subagent-control.accepted-stop.test.ts": "owned fixture correction\n",
            "scripts/generate-npm-package-lock.mts": "owned generator correction\n",
            "test/scripts/generate-npm-package-lock.test.ts": "owned generator regression\n",
        }
        source = f.remediation_source(writes=writes)
        release.check_source_graph(source, f.root)
        self.assertEqual(json.loads(git(f.root, "show", f.integration + ":" + LEDGER)), f.ledger)
        self.assertIs(f.manifest108["productionEligible"], False)

    def test_approved_fixture_generator_paths_do_not_authorize_neighbors(self):
        for name in (
            "src/agents/subagents/registry/subagent-control.accepted-stop.ts",
            "scripts/generate-npm-package-lock-other.mts",
            "test/scripts/generate-npm-package-lock-other.test.ts",
        ):
            with self.subTest(path=name):
                self.refused(self.fixture.remediation_source(writes={name: "unreviewed neighboring change\n"}),
                             "unreviewed path")

    def test_approved_fixture_generator_paths_keep_mode_blob_and_ledger_guards(self):
        for name in (
            "src/agents/subagents/registry/subagent-control.accepted-stop.test.ts",
            "scripts/generate-npm-package-lock.mts",
            "test/scripts/generate-npm-package-lock.test.ts",
        ):
            with self.subTest(path=name, guard="mode"):
                self.refused(self.fixture.remediation_source(writes={name: "owned correction\n"}, modes=(name,)),
                             "mode changed")
            with self.subTest(path=name, guard="coverage"):
                self.refused(self.fixture.remediation_source(writes={name: "owned correction\n"},
                             mutate_ledger=lambda x: x.update(paths=[r for r in x["paths"] if r["path"] != name])),
                             "coverage")
            with self.subTest(path=name, guard="disposition"):
                self.refused(self.fixture.remediation_source(writes={name: "owned correction\n"},
                             mutate_ledger=lambda x: next(r for r in x["paths"] if r["path"] == name).update(
                                 disposition="CARRIED_EXACT")), "disposition or mode")
            with self.subTest(path=name, guard="blob"):
                self.refused(self.fixture.remediation_source(writes={name: "owned correction\n"},
                             mutate_ledger=lambda x: next(r for r in x["paths"] if r["path"] == name)["result"].update(
                                 blob="0" * 40)), "mode/blob changed")

    def test_remediation_disposition_is_not_allowed_on_integration_or_other_paths(self):
        f = self.fixture
        self.changed_ledger_refused(lambda x: next(r for r in x["paths"] if r["path"] == SECURITY).update(
            disposition=release.V108_REMEDIATION), "unsupported 10.8 disposition")
        self.refused(f.remediation_source(writes={SECURITY: "unreviewed runtime change\n"}),
                     "unreviewed path")

    def test_successor_cannot_change_an_unchanged_historical_row(self):
        name = "test/v108-remediation-security.test.mjs"
        self.refused(self.fixture.remediation_source(writes={name: "synthetic new test\n"},
                     mutate_ledger=lambda x: next(r for r in x["paths"] if r["path"] == SECURITY).update(
                         disposition=release.V108_REMEDIATION)), "historical reconciliation changed")

    def test_successor_cannot_hide_an_invalid_original_integration(self):
        f = self.fixture
        ledger = copy.deepcopy(f.ledger)
        changed = f.replaced_source(writes={SECURITY: "unreviewed historical change\n"})
        next(r for r in ledger["paths"] if r["path"] == SECURITY)["result"] = f.entry(changed["commit"], SECURITY)
        bad = f.replaced_source(ledger=ledger, writes={SECURITY: "unreviewed historical change\n"})
        commit = f.commit_tree(f.tree(bad["commit"]), [bad["commit"]])
        source = copy.deepcopy(bad)
        source.update(**f.identity(commit), patches=[f.identity(commit)])
        source["merge"]["successors"] = [f.identity(commit)]
        self.refused(source, "exact fork carry")

    def test_package_remediation_cannot_change_runtime_security_or_scripts(self):
        for name in ("package.json", UI_PACKAGE):
            document = self.package_repair(name)
            document["scripts"] = {"check": "unreviewed"}
            self.refused(self.fixture.remediation_source(writes={name: encoded(document)}),
                         "unrelated package metadata")
        document = self.package_repair("package.json")
        document["dependencies"]["security-parent"] = "1.0.0"
        self.refused(self.fixture.remediation_source(writes={"package.json": encoded(document)}),
                     "unrelated package metadata")
        document = self.package_repair("package.json")
        document["devDependencies"]["vitest"] = "5.0.6"
        self.refused(self.fixture.remediation_source(writes={"package.json": encoded(document)}),
                     "unrelated package metadata")

    def test_workspace_remediation_cannot_disable_security_or_add_overrides(self):
        for value in (WORKSPACE_AFTER.replace("minimumReleaseAgeStrict: true", "minimumReleaseAgeStrict: false"),
                      WORKSPACE_AFTER + "  unreviewed: 1.0.0\n", WORKSPACE_BEFORE):
            source = self.fixture.remediation_source(writes={WORKSPACE: value})
            if value == WORKSPACE_BEFORE:
                release.check_source_graph(source, self.fixture.root)  # No workspace change to claim.
            else:
                self.refused(source, "unrelated workspace policy")

    def test_patch_retirement_is_only_allowed_with_exact_versioned_replacement(self):
        f = self.fixture
        self.refused(f.remediation_source(removals=(OLD_PATCH,)), "no reviewed replacement")
        self.refused(f.remediation_source(writes={NEW_PATCH: "replacement\n"}), "retained the obsolete")
        self.refused(f.remediation_source(writes={NEW_PATCH: "replacement\n"}, removals=(OLD_PATCH,),
                     mutate_ledger=lambda x: next(r for r in x["paths"] if r["path"] == OLD_PATCH).update(
                         disposition=release.V108_REMEDIATION)), "no reviewed replacement")
        self.refused(f.remediation_source(writes={NEW_PATCH: "replacement\n"},
                     removals=(OLD_PATCH,), modes=(NEW_PATCH,)), "mode changed")

    def test_patch_replacement_requires_all_metadata_alignment(self):
        f = self.fixture
        writes = {NEW_PATCH: "rebased Vitest worker patch\n",
                  "package.json": encoded(self.package_repair("package.json")),
                  UI_PACKAGE: encoded(self.package_repair(UI_PACKAGE)), WORKSPACE: WORKSPACE_AFTER}
        for missing in ("package.json", UI_PACKAGE, WORKSPACE):
            incomplete = {name: value for name, value in writes.items() if name != missing}
            self.refused(f.remediation_source(writes=incomplete, removals=(OLD_PATCH,)),
                         "unrelated package metadata|unrelated workspace policy")

    def test_successor_mode_or_disposition_drift_is_rejected(self):
        name = REPAIR_TESTS[0]
        self.refused(self.fixture.remediation_source(writes={name: "fixture repair\n"}, modes=(name,)),
                     "mode changed")
        self.refused(self.fixture.remediation_source(writes={name: "fixture repair\n"},
                     mutate_ledger=lambda x: next(r for r in x["paths"] if r["path"] == name).update(
                         disposition="CARRIED_EXACT")), "disposition or mode")

    def test_unreviewed_intermediate_change_is_rejected_even_after_revert(self):
        f = self.fixture
        git(f.root, "reset", "--hard", f.integration)
        f.write("unreviewed.txt", "intermediate change\n")
        first = f.commit("unreviewed intermediate")
        final = f.commit_tree(f.tree(f.integration), [first])
        source = copy.deepcopy(f.source108)
        source.update(**f.identity(final), patches=[f.identity(final)])
        source["merge"]["successors"] = [f.identity(first), f.identity(final)]
        self.refused(source, "successor history changed")

    def test_zero_successors_require_integration_tip_and_v2_stays_strict(self):
        value = self.fixture.successor_source(1)
        value["merge"]["successors"] = []
        self.refused(value, "successor tip")
        value = copy.deepcopy(self.fixture.source108)
        value["merge"]["schema"] = "openclaw.fork-source-merge.v2"
        self.refused(value, "successor count")

    def test_successor_linear_parent_order_and_identity_are_checked(self):
        f = self.fixture
        value = f.successor_source(2)
        value["merge"]["successors"].reverse()
        self.refused(value)
        value = f.successor_source(2)
        value["merge"]["successors"].pop(0)
        self.refused(value)
        value = f.successor_source(1)
        value["merge"]["successors"].insert(0, value["merge"]["integration"])
        self.refused(value)
        commit = f.commit_tree(f.tree(f.integration), [f.integration, f.upstream])
        value = f.successor_source(1)
        value.update(**f.identity(commit), patches=[f.identity(commit)])
        value["merge"]["successors"] = [f.identity(commit)]
        self.refused(value, "successor parent or tree")

    def test_wrong_parents_and_every_tree_and_common_ancestor_are_refused(self):
        f = self.fixture
        for parents in ([f.upstream, f.fork], [f.common, f.upstream], [f.fork, f.upstream, f.common]):
            self.refused(f.replaced_source(parents=parents), "ordered parents")
        for owner, field in (("source", "baseTree"), ("source", "tree"), ("merge", "forkTree"),
                             ("merge", "commonTree"), ("integration", "tree"), ("securitySource", "tree")):
            value = copy.deepcopy(f.source108)
            target = value if owner == "source" else value["merge"] if owner == "merge" else value["merge"][owner]
            target[field] = "0" * 40
            if owner == "source" and field == "tree":
                value["patches"][0]["tree"] = "0" * 40
            self.refused(value)
        value = copy.deepcopy(f.source108)
        value["merge"].update(commonCommit=f.fork, commonTree=f.tree(f.fork))
        self.refused(value, "common ancestor")

    def test_closed_schema_types_dispositions_and_qualification(self):
        mutations = [lambda x: x.update(qualificationTransferred=True), lambda x: x.update(extra="unreviewed"),
                     lambda x: x.update(priorForkDeltaPaths=True), lambda x: x.update(textualConflicts=True),
                     lambda x: x.update(textualConflicts=1), lambda x: x.update(schema="old-ledger"),
                     lambda x: x["paths"][0].update(extra="unreviewed"),
                     lambda x: x["paths"][0].update(disposition="RETIRED"),
                     lambda x: x["paths"][0].update(disposition=["CARRIED_EXACT"]),
                     lambda x: x["paths"][0]["result"].update(extra="unreviewed")]
        for mutate in mutations:
            self.changed_ledger_refused(mutate)
        for key, replacement in (("extra", "unreviewed"), ("schema", "openclaw.fork-source-merge.v4")):
            source = copy.deepcopy(self.fixture.source108)
            source["merge"][key] = replacement
            self.refused(source)

    def test_every_origin_and_result_mode_and_blob_are_checked(self):
        f = self.fixture
        for key in ("upstream107", "fork107", "upstream108", "result"):
            for field, replacement in (("blob", "0" * 40), ("mode", "100755")):
                self.changed_ledger_refused(lambda x: next(r for r in x["paths"] if r["path"] == "package.json")[key].update({field: replacement}), "mode/blob changed")
        self.refused(f.replaced_source(writes={SECURITY: "unreviewed\n"}), "mode/blob changed")
        self.refused(f.replaced_source(modes=(SECURITY,)), "mode/blob changed")

    def test_all_prior_fork_and_new_result_paths_are_covered(self):
        for name in (WORKBOARD, SECURITY, NOTE):
            self.changed_ledger_refused(lambda x: x.update(paths=[r for r in x["paths"] if r["path"] != name]), "coverage")
        self.changed_ledger_refused(lambda x: x["paths"].append(x["paths"][0]), "coverage")
        self.refused(self.fixture.replaced_source(writes={"unreviewed.txt": "new result delta\n"}), "coverage")
        self.changed_ledger_refused(lambda x: x.update(priorForkDeltaPaths=0), "path count")

    def test_only_the_exact_ledger_self_exclusion_is_permitted(self):
        for exclusion in ({"path": SECURITY, "reason": "result-blob self-reference excluded"},
                          {"path": LEDGER, "reason": "omit other paths"},
                          {"path": LEDGER, "reason": "result-blob self-reference excluded", "also": SECURITY}):
            self.changed_ledger_refused(lambda x: x.update(selfExclusion=exclusion), "self-exclusion")

    def test_honestly_rebound_retirement_and_exact_carry_mutation_fail(self):
        f = self.fixture
        for name in (WORKBOARD, SECURITY):
            self.changed_ledger_refused(lambda x: next(r for r in x["paths"] if r["path"] == name).update(result=None),
                                        "cannot retire", removals=(name,))
        changed = f.replaced_source(writes={SECURITY: "downgrade\n"})
        entry = f.entry(changed["commit"], SECURITY)
        self.changed_ledger_refused(lambda x: next(r for r in x["paths"] if r["path"] == SECURITY).update(result=entry),
                                    "exact fork carry", writes={SECURITY: "downgrade\n"})
        self.changed_ledger_refused(lambda x: next(r for r in x["paths"] if r["path"] == SECURITY).update(
            result=entry, disposition="MERGED_TASK_ACCESS_AND_IMMUTABLE_INSPECTION"),
            "unsupported 10.8 disposition", writes={SECURITY: "downgrade\n"})

    def test_dependency_override_workboard_and_script_downgrades_fail(self):
        f = self.fixture
        for name, mutate in (("package.json", lambda x: x["dependencies"].update({"security-parent": "1.0.0"})),
                             ("package.json", lambda x: x["pnpm"]["overrides"].update({"security-child": "1.0.0"})),
                             (PACKAGES[1], lambda x: x["dependencies"].update({"security-parent": "1.0.0"})),
                             ("package.json", lambda x: x["scripts"].update(check="unreviewed"))):
            document = json.loads(git(f.root, "show", f.integration + ":" + name))
            mutate(document)
            writes = {name: encoded(document)}
            changed = f.replaced_source(writes=writes)
            entry = f.entry(changed["commit"], name)
            self.changed_ledger_refused(lambda x: next(r for r in x["paths"] if r["path"] == name).update(result=entry),
                                        "dependency security or fork metadata", writes=writes)

    def test_digest_source_bindings_and_mode_claims_are_checked(self):
        f = self.fixture
        value = copy.deepcopy(f.source108)
        value["merge"]["reconciliation"]["sha256"] = "0" * 64
        self.refused(value, "digest changed")
        for key in ("upstream107", "fork107Source", "upstream108"):
            self.changed_ledger_refused(lambda x: x.update({key: "0" * 40}), "source binding")
        for entry in ({"mode": "040000", "blob": "0" * 40}, {"mode": "100644", "blob": "bad"}):
            self.changed_ledger_refused(lambda x: x["paths"][0].update(result=entry), "invalid 10.8 ledger mode/blob")

    def test_preflight_shares_graph_and_annotated_tag_binding(self):
        f = self.fixture
        for tag in (f.tag_object(f.fork), f.tag_object(f.upstream, "v2026.10.7")):
            checks = preflight.Checks()
            preflight.source_checks(checks, f.manifest108, f.root, [], None,
                                    {"tag": "v2026.10.8", "tagObject": tag}, check_head=False)
            self.assertIn("upstream.tag.binding", checks.errors)
        checks = preflight.Checks()
        preflight.source_checks(checks, f.manifest108, f.root, [], None,
                                {"tag": "v2026.10.8", "tagObject": f.tag108}, check_head=False)
        self.assertEqual(checks.errors, [])
        manifest = copy.deepcopy(f.manifest108)
        manifest["source"] = f.replaced_source(parents=[f.upstream, f.fork])
        checks = preflight.Checks()
        preflight.source_checks(checks, manifest, f.root, [], None, check_head=False)
        self.assertIn("source.graph.refused", checks.errors)

    def test_v3_history_has_security_integration_and_all_successors(self):
        f = self.fixture
        manifest = copy.deepcopy(f.manifest108)
        manifest["source"] = f.successor_source(2)
        inventory = {"patches": [{"originCommit": f.fork, "paths": [{"sourceCommit": f.fork}]}]}
        actual = preflight.history_commits(inventory, manifest)
        expected = {f.common, f.fork, f.upstream, f.integration, f.security}
        expected.update(r["commit"] for r in manifest["source"]["merge"]["successors"])
        self.assertEqual(actual, sorted(expected))

    def test_shallow_and_missing_history_are_refused_without_fetch(self):
        f = self.fixture
        shallow = f.root / ".git/shallow"
        try:
            shallow.write_text(f.fork + "\n")
            self.refused(f.source108, "ancestry is shallow")
        finally:
            shallow.unlink(missing_ok=True)
        value = copy.deepcopy(f.source108)
        value["merge"]["securitySource"]["commit"] = "0" * 40
        with self.assertRaises((release.Refusal, subprocess.CalledProcessError)):
            release.check_source_graph(value, f.root)


if __name__ == "__main__":
    unittest.main()
