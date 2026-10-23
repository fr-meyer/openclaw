"""Additive next-release policy proof with synthetic source and no cloud calls."""

import copy
import hashlib
import json
from unittest.mock import patch
import unittest

import gcp_build as build
import release
import test_gcp_build as legacy


class NextReleaseBuildTests(unittest.TestCase):
    git = legacy.BuildTests.git
    prepare = legacy.BuildTests.prepare
    cache_fixture = legacy.BuildTests.cache_fixture
    adaptive_fixture = legacy.BuildTests.adaptive_fixture
    qualification_fixture = legacy.BuildTests.qualification_fixture

    def setUp(self):
        legacy.BuildTests.setUp(self)
        manifest = json.loads(self.manifest.read_bytes())
        inventory = json.loads(self.inventory.read_bytes())
        base = manifest["source"]["baseCommit"]
        self.next_dockerfile = self.dockerfile + b"# next release label fixture\n"
        (self.source / "Dockerfile").write_bytes(self.next_dockerfile)
        (self.source / "package.json").write_text('{"version":"2026.10.6"}\n')
        self.git("add", ".")
        self.git("commit", "--quiet", "--amend", "--no-edit")
        sha, tree = self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")
        self.git("tag", "-a", "v2026.10.6", base, "-m", "synthetic next release")
        manifest["candidate"] = "v2026.10.6-source-only"
        manifest["source"].update({"commit": sha, "tree": tree,
                                  "patches": [{"commit": sha, "tree": tree}]})
        manifest["review"].update({"prNumber": 19, "changedDiffSha256": release.sha256(
            build.pr.git(self.source, "diff", "--binary", "--full-index", "--no-ext-diff",
                         base, sha, binary=True))})
        self.manifest.write_bytes(build.encode(manifest))
        inventory.update({"candidate": manifest["candidate"],
                          "manifestSha256": build.preflight.digest(self.manifest)})
        inventory["upstream"].update({"tag": "v2026.10.6",
                                       "tagObject": self.git("rev-parse", "v2026.10.6")})
        entry = inventory["patches"][0]
        entry["appliedCommit"] = sha
        for path in ("Dockerfile", "package.json"):
            old_blob = self.git("rev-parse", f"{base}:{path}")
            entry["paths"].append({
                "path": path, "boundary": "container", "sourceCommit": base,
                "sourceTree": manifest["source"]["baseTree"], "sourceBlob": old_blob,
                "upstreamBlob": old_blob, "candidateBlob": self.git("rev-parse", f"{sha}:{path}"),
            })
        self.inventory.write_bytes(build.encode(inventory))
        self.config.update({"sourceSha": sha, "sourceTree": tree,
                            "manifestSha256": build.preflight.digest(self.manifest),
                            "inventorySha256": build.preflight.digest(self.inventory)})
        self.stack.enter_context(patch.object(build, "NEXT_QUALIFICATION_SOURCE_SHA", sha))
        self.stack.enter_context(patch.object(build, "NEXT_QUALIFICATION_SOURCE_TREE", tree))
        self.stack.enter_context(patch.object(build, "NEXT_REVIEWED_DOCKERFILE_SHA256",
                                             hashlib.sha256(self.next_dockerfile).hexdigest()))

    def test_exact_next_source_selects_existing_bounded_profile(self):
        samples = self.qualification_fixture()
        bound = build.bind_adaptive_selection(self.config, samples)
        self.assertEqual(bound["adaptiveSelection"]["profile"]["id"], build.QUALIFICATION_PROFILE_ID)
        self.assertEqual(bound["adaptiveSelection"]["profile"]["qualification"], "candidate-unqualified")
        self.assertEqual(bound["buildTuning"], {"tsdownMaxOldSpaceMb": 6144})
        self.assertEqual(bound["builder"]["memoryBytes"], 8 << 30)
        self.assertEqual(bound["builder"]["memorySwapBytes"], 8 << 30)
        self.assertEqual(bound["builder"]["cpuQuota"], 400000)
        self.assertEqual(bound["limits"]["minStartMemoryAvailableBytes"], 10 << 30)
        self.assertEqual(bound["limits"]["minMemoryAvailableBytes"], 2 << 30)
        self.assertTrue(build.duration_aware_running_pressure(bound))
        build.validate_config(bound)

    def test_next_source_retains_memory_health_pressure_and_disk_admission(self):
        samples = self.qualification_fixture()
        for key, value in (("memoryAvailableBytes", (10 << 30) - 1),
                           ("freeBytes", (16 << 30) - 1),
                           ("cacheFreeBytes", (44 << 30) - 1),
                           ("fullMemoryPressureAvg10", 5.01),
                           ("gatewayHealthy", False), ("gatewayOomKilled", True)):
            with self.subTest(key=key):
                changed = copy.deepcopy(samples)
                changed[1][key] = value
                self.assertIsNone(build.bind_adaptive_selection(self.config, changed))
        stale = [{**row, "observedAt": "2000-01-01T00:00:00Z"} for row in samples]
        with self.assertRaises(release.Refusal):
            build.bind_adaptive_selection(self.config, stale)

    def test_next_source_rejects_wrong_tree_and_changed_worker_envelope(self):
        samples = self.qualification_fixture()
        wrong = copy.deepcopy(self.config)
        wrong["sourceTree"] = "f" * 40
        for changed in (wrong, *[
            {**self.config, "builder": {**self.config["builder"], key: value}}
            for key, value in (("memoryBytes", 9 << 30), ("memorySwapBytes", 9 << 30),
                               ("cpuQuota", 500000))
        ]):
            with self.subTest(changed=changed["builder"]), \
                 self.assertRaises(release.Refusal):
                build.bind_adaptive_selection(changed, samples)
            with self.assertRaises(release.Refusal):
                build.validate_config(changed)
        unknown = {**self.config, "sourceSha": "f" * 40}
        self.assertFalse(build.is_selectable_qualification_source(unknown))
        self.assertIsNone(build.bind_adaptive_selection(unknown, samples))

    def test_real_source_binding_and_preparation_use_next_digest_version_and_tag(self):
        samples = self.qualification_fixture()
        bound = build.bind_adaptive_selection(self.config, samples)
        op = self.prepare(bound)
        _, intent = build.load_intent(op)
        self.assertEqual(intent["version"], "2026.10.6")
        command = intent["buildArgv"]
        self.assertEqual(command[command.index("--tag") + 1],
                         f"openclaw-v106-prep:{bound['sourceSha'][:12]}")
        self.assertIn("OPENCLAW_DOCKER_BUILD_VERSION=2026.10.6", command)
        self.assertIn("OPENCLAW_DOCKER_BUILD_TSDOWN_MAX_OLD_SPACE_MB=6144", command)
        self.assertIn("OPENCLAW_EXTENSIONS=codex,workboard", command)
        self.assertEqual(command[-1], "https://github.com/fr-meyer/openclaw.git"
                         f"?fetch-by-commit=true&checksum={bound['sourceSha']}#{bound['sourceSha']}")
        self.assertEqual(set(intent["supervisorSha256"]), set(build.HELPERS))

    def test_next_dockerfile_pin_is_not_a_global_allowlist(self):
        samples = self.qualification_fixture()
        bound = build.bind_adaptive_selection(self.config, samples)
        with patch.object(build, "NEXT_REVIEWED_DOCKERFILE_SHA256",
                          hashlib.sha256(self.dockerfile).hexdigest()), \
             self.assertRaisesRegex(release.Refusal, "network_policy_unreviewed"):
            self.prepare(bound)
        # The same real synthetic source loses access to the next Dockerfile
        # if its exact source identity is no longer the reviewed next source.
        with patch.object(build, "NEXT_QUALIFICATION_SOURCE_SHA", "f" * 40), \
             self.assertRaisesRegex(release.Refusal, "network_policy_unreviewed"):
            build.source_binding(bound, self.manifest, self.inventory, self.source)

    def test_next_command_refuses_wrong_release_or_source_identity(self):
        self.qualification_fixture()
        for changed, version in ((self.config, "2026.10.5"),
                                 ({**self.config, "sourceTree": "f" * 40}, "2026.10.6"),
                                 ({**self.config, "sourceSha": "f" * 40}, "2026.10.6")):
            with self.subTest(version=version), \
                 self.assertRaisesRegex(release.Refusal, "next_source_mismatch"):
                build.build_argv(self.root, changed, version)
        legacy_config = {**self.config, "sourceSha": build.QUALIFICATION_SOURCE_SHA}
        legacy_command = build.build_argv(self.root, legacy_config, "2026.10.5")
        self.assertEqual(legacy_command[legacy_command.index("--tag") + 1],
                         f"openclaw-v105-prep:{build.QUALIFICATION_SOURCE_SHA[:12]}")

    def test_next_prepare_requires_adaptive_profile_and_start_still_checks_cgroup(self):
        samples = self.qualification_fixture()
        with self.assertRaisesRegex(release.Refusal, "current_profile_required"):
            self.prepare()
        op = self.prepare(build.bind_adaptive_selection(self.config, samples))
        with patch.object(build, "collect_adaptive_samples", return_value=samples), \
             patch.object(build, "verify_builder_cgroup_limits",
                          side_effect=release.Refusal("synthetic wrong cgroup")), \
             patch.object(build, "native") as native:
            with self.assertRaisesRegex(release.Refusal, "synthetic wrong cgroup"):
                build.start(op)
            native.assert_not_called()
        self.assertFalse((op / "start-intent.json").exists())

    def test_retained_sources_are_not_newly_selectable_and_cross_release_handoff_is_not_added(self):
        samples = self.qualification_fixture()
        next_bound = build.bind_adaptive_selection(self.config, samples)
        for sha in (build.RETAINED_QUALIFICATION_SOURCE_SHA,
                    build.HISTORICAL_QUALIFICATION_SOURCE_SHA):
            retained = {**self.config, "sourceSha": sha}
            self.assertFalse(build.is_selectable_qualification_source(retained))
            self.assertIsNone(build.select_profile(retained, samples))
            self.assertFalse(build.prepared_binding_compatible(
                {"config": retained}, {"config": next_bound}))
        old = {**next_bound, "sourceSha": build.QUALIFICATION_SOURCE_SHA}
        self.assertFalse(build.prepared_binding_compatible(
            {"config": old}, {"config": next_bound}))


if __name__ == "__main__":
    unittest.main()
