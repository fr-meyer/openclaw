"""Pure unapplied-proposal tests; no image/native/host-control execution."""
import copy
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest


BASE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("v98_inert_openssl_proposal",
                                              BASE / "proposal/render_delta.py")
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)
PROPOSED_DERIVE_SHA = "bce4fb6fd9150e02a553df09042859e7654ed2f6278880ac48fc0ccbfb953b09"
FIXTURE_SIZING_DERIVE_SHA = "407010cefebfbb9a05fc48bc9c70da9f8d44e5f81f7e32e52cf98a2899f5977c"
FIXTURE_SIZING_SHA = "0c3b33ee321e88dea9f47b13d0eaec84dc11b60a8fbaeb2a72df7ca96890577d"
FIXTURE_SIZING_STATE_SHA = "6b53fb7f426678a3962f7746bd26feea2f3d840cc896d51a8a740a9e0dbada3e"


# Test-only recovery of the exact image-pin cutover. The proposal renderer
# retains its historical BC8 capture and refuses every repinned source.
IMAGE_REBOUND_DERIVE_SHA = "1f2118ad51f35969afb16163c4aa840075fba590cf0addacde287b370510638d"
IMAGE_REBOUND_DERIVE_INVERSE = (
    ("SOURCE_COMMIT = \"fe1b334f74f1e43efc22f91c1c3738e59c52519c\"",
     "SOURCE_COMMIT = \"bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf\""),
    ("SOURCE_TREE = \"5da503ec4fdd8242a5caf71ae8bfc1621c8996f3\"",
     "SOURCE_TREE = \"ba825f670dc5ba943f7893cb267225d1f68d3110\""),
    ("IMAGE_SHA256 = \"4efe7e2ab51c0bd4052b1fb4b50edd84df02720a320aa988ce97cad55f4bfa00\"",
     "IMAGE_SHA256 = \"0a3418e393313dbe7e20f4ef140fea81e3a7e6d8a24f9ee1bf5e0bd87d86ffcf\""),
    ("IMAGE_CONFIG = \"sha256:ac50e2b36804c5d0db9586d6fe545f90a00140cdfb498abe3c55da1564733a19\"",
     "IMAGE_CONFIG = \"sha256:1b2669dcea79d48e6c9f1e86a81495746e62f6d4b9a7837eaccca5ce0a266c39\""),
    ("    \"graph\": (\"runtime-binding/analysis/graph.json\", \"7eaaa86bab0597f69d9208bc77140fff605a9dfb922a283738d5a0cd847b9589\"),",
     "    \"graph\": (\"openclaw-v98-doctor-worker-import-graph-final-20261004.json\", \"7eaaa86bab0597f69d9208bc77140fff605a9dfb922a283738d5a0cd847b9589\"),"),
    ("    \"inventory\": (\"validated-initial/image-filesystem-manifest.json.gz\", \"127796387c90a0ce5887f8978990823c14f983506e7cea1ac1c5b91926c5078d\"),",
     "    \"inventory\": (\"openclaw-v98-artifact-build-37192724704-validated-scalable/image-filesystem-manifest.json.gz\", \"e7c50cfcb33072e780dbae849147d3fbc33b2bcb41b7067ae9f13a05d9116719\"),"),
    ("    \"catalog\": (\"runtime-binding/analysis/catalog.json\", \"38193b2c93f0ee1f72d68f07cf7198fd96c4a3554081ed1eab0ff0687a37e7e0\"),",
     "    \"catalog\": (\"openclaw-v98-independent-final-catalog-join-20261004.json\", \"61fdb2ab3746f01126f518bc4d57e86311501ce9b29a6e1dc8bba2a41bb52328\"),"),
    ("    \"classification\": (\"runtime-binding/analysis/classification.json\", \"6ef653754a3730cb6fcaa6071fab9b3150aa84f902d3c05a5e2e564bbe5b9557\"),",
     "    \"classification\": (\"openclaw-v98-independent-final-catalog-classification-20261004.json\", \"0a051c803837686a67627abf6e417dbcc5c7893c62c76882abf9fe6417c8f290\"),"),
    ("    \"elf\": (\"runtime-binding/analysis/elf.json\", \"f322753bb2d60fff94305b6187e0fbac6686d56a1ed56207bce847701fb7f108\"),",
     "    \"elf\": (\"openclaw-v98-elf-dependency-analysis-20261004.json\", \"1de4df7cfd908935ee5703df95ebd75d1a39ed04e96867969e7e1c2e9a0e1555\"),"),
)


LAZY_SUBAGENT_DERIVE_SHA = "692433db84c7b7bbda05927b4e6d451d60b11868cc80e2226a17d72c723a2549"
LAZY_SUBAGENT_FIXTURE_SHA = "25eedca246b608355018e5c43fb0e0ff86d3c5473e445121b5cf4346124a9b0f"


def baseline_source(raw):
    """Test fixture only: invert exact pinned revisions to the historical baseline."""
    if RENDER.digest(raw) == LAZY_SUBAGENT_DERIVE_SHA:
        pin = '"/proof/inputs/fixture.mjs": "'
        text = raw.decode("utf-8")
        if text.count(pin + LAZY_SUBAGENT_FIXTURE_SHA) != 1:
            raise ValueError("first-use fixture pin inverse anchor changed")
        raw = text.replace(pin + LAZY_SUBAGENT_FIXTURE_SHA,
                           pin + FIXTURE_SIZING_SHA, 1).encode("utf-8")
        if RENDER.digest(raw) != IMAGE_REBOUND_DERIVE_SHA:
            raise ValueError("first-use fixture inverse did not restore exact image source")
    if RENDER.digest(raw) == IMAGE_REBOUND_DERIVE_SHA:
        text = raw.decode("utf-8")
        for new, old in IMAGE_REBOUND_DERIVE_INVERSE:
            if text.count(new) != 1:
                raise ValueError("image pin inverse anchor changed")
            text = text.replace(new, old, 1)
        raw = text.encode("utf-8")
        if RENDER.digest(raw) != FIXTURE_SIZING_DERIVE_SHA:
            raise ValueError("image pin inverse did not restore exact fixture source")
    if RENDER.digest(raw) == FIXTURE_SIZING_DERIVE_SHA:
        pin = '"/proof/inputs/fixture.mjs": "'
        text = raw.decode("utf-8")
        if text.count(pin + FIXTURE_SIZING_SHA) != 1:
            raise ValueError("fixture pin inverse anchor changed")
        raw = text.replace(pin + FIXTURE_SIZING_SHA, pin + "777936fa311d3b6fb141dff1fc67f46e2cfddf0651bf75b30ae62f74368f674e").encode("utf-8")
        state_pin = '"/proof/inputs/predecessor-state.sql": "'
        text = raw.decode("utf-8")
        if text.count(state_pin + FIXTURE_SIZING_STATE_SHA) != 1:
            raise ValueError("predecessor pin inverse anchor changed")
        raw = text.replace(state_pin + FIXTURE_SIZING_STATE_SHA,
                           state_pin + "32a9ec60e38f1511e6f5fcd532f4c631d680d537a8325601f5bdf8221cf20fa3").encode("utf-8")
        if RENDER.digest(raw) != PROPOSED_DERIVE_SHA:
            raise ValueError("fixture pin inverse did not restore exact projection")
    if RENDER.digest(raw) == RENDER.DERIVE_SHA:
        return raw
    if RENDER.digest(raw) != PROPOSED_DERIVE_SHA:
        raise ValueError("test derivation source is neither exact baseline nor projection")
    text = raw.decode("utf-8")
    selection = '    "/etc/ld.so.cache",\n    "/etc/ssl/openssl.cnf",\n)'
    elf = ('    elf_files = tuple(path for path in SYSTEM_FILES\n'
           '                      if path not in ("/etc/ld.so.cache", "/etc/ssl/openssl.cnf"))\n'
           '    for path in (GNU_FS_SAFE, GNU_KOFFI) + elf_files:')
    if text.count(selection) != 1 or text.count(elf) != 1:
        raise ValueError("projected test inverse anchors changed")
    original = text.replace(selection, '    "/etc/ld.so.cache",\n)').replace(
        elf, '    for path in (GNU_FS_SAFE, GNU_KOFFI) + SYSTEM_FILES[:-1]:').encode("utf-8")
    if RENDER.digest(original) != RENDER.DERIVE_SHA:
        raise ValueError("projected test inverse does not restore exact baseline")
    return original


def synthetic_inputs(active):
    # Small metadata only. No retained-image binary or module is loaded.
    paths = list(active["APP_METADATA"]) + list(active["SYSTEM_FILES"])
    paths += [active["GNU_FS_SAFE"], active["GNU_KOFFI"], "/app/dist/doctor.mjs"]
    directories = {str(parent) for path in paths + [RENDER.CONFIG["path"],
                                                    "/usr/lib/ssl/openssl.cnf"]
                   for parent in PurePosixPath(path).parents if str(parent) != "/"}
    entries = {path: {"path": path, "mode": "0o755", "type": "directory"}
               for path in directories}
    entries.update({path: {"path": path, "mode": "0o644", "type": "file",
                           "bytes": 1, "sha256": RENDER.digest(b"x")} for path in paths})
    entries[RENDER.CONFIG["path"]] = dict(RENDER.CONFIG)
    alias = RENDER.NAMESPACE[1]
    entries[alias["path"]] = dict(alias)
    elf = [dict(entries[path]) for path in (active["GNU_FS_SAFE"], active["GNU_KOFFI"])
           + active["SYSTEM_FILES"][:-1]]
    next(row for row in elf if row["path"] == active["NODE"])["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
    return {
        "graph": {"schema": "openclaw-v98-static-import-graph/v1", "completeClosureClaimed": False,
                  "imageJavaScriptExecuted": False, "files": [dict(entries["/app/dist/doctor.mjs"])],
                  "metadata": [], "unresolved": []},
        "inventory": {"schema": "openclaw-image-filesystem-inventory/v1", "entries": list(entries.values())},
        "catalog": {"schema": "openclaw-v98-independent-final-catalog-join/v1",
                    "imageSha256": active["IMAGE_SHA256"], "imageConfigId": active["IMAGE_CONFIG"],
                    "inventorySha256": active["PINNED_INPUTS"]["inventory"][1],
                    "runtimeExecuted": False, "differences": []},
        "classification": {"rawReceiptSha256": active["PINNED_INPUTS"]["catalog"][1],
                           "waiverOrExecutionAdmission": False},
        "elf": {"entries": elf},
    }


class OpenSSLProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = baseline_source((BASE / "derive_read_policy.py").read_bytes())
        cls.active = RENDER._inert_deriver(cls.source)
        cls.inputs = synthetic_inputs(cls.active)
        cls.before = cls.active["derive_binding"](**cls.inputs)
        reads = cls.active["read_list_bytes"](cls.active["image_read_paths"](cls.before))
        cls.current = {RENDER.BINDING: RENDER.json_bytes(cls.before),
                       RENDER.PARENT: reads, RENDER.HELPER: reads}

    def test_exact_one_file_two_metadata_delta_and_no_elf_config_requirement(self):
        files, before, after = RENDER._derive_projection(self.source, self.inputs, self.current)
        self.assertEqual(set(files), {RENDER.DERIVE, RENDER.BINDING, RENDER.PARENT, RENDER.HELPER})
        old = {row["path"]: row for row in before["imageEntries"]}
        new = {row["path"]: row for row in after["imageEntries"]}
        self.assertEqual(set(new) - set(old), {RENDER.CONFIG["path"]})
        self.assertEqual(new[RENDER.CONFIG["path"]],
                         {**RENDER.CONFIG, "reasons": ["named-node-and-gnu-loader-runtime"]})
        self.assertTrue(all(new[path] == row for path, row in old.items()))
        old_namespace = {row["path"]: row for row in before["namespaceEntries"]}
        added = [row for row in after["namespaceEntries"] if row["path"] not in old_namespace]
        self.assertEqual(added, RENDER.NAMESPACE)
        self.assertEqual(files[RENDER.PARENT], files[RENDER.HELPER])
        self.assertNotIn(b"/etc/ssl/openssl.cnf\n", self.current[RENDER.PARENT])
        self.assertIn(b"/etc/ssl/openssl.cnf\n", files[RENDER.PARENT])
        self.assertFalse(after["runtimeExecuted"])
        self.assertFalse(after["readPolicy"]["directoryReadRules"])
        self.assertFalse(after["completeImportClosureClaimed"])
        # ELF inventory deliberately contains neither cache nor configuration.
        self.assertFalse(any(row["path"] in ("/etc/ld.so.cache", RENDER.CONFIG["path"])
                             for row in self.inputs["elf"]["entries"]))

    def test_config_identity_and_alias_target_drift_cannot_broaden_projection(self):
        for path, field, value in ((RENDER.CONFIG["path"], "sha256", "0" * 64),
                                   (RENDER.NAMESPACE[1]["path"], "target", "/etc/ld.so.cache")):
            inputs = copy.deepcopy(self.inputs)
            next(row for row in inputs["inventory"]["entries"] if row["path"] == path)[field] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                RENDER._derive_projection(self.source, inputs, self.current)

    def test_baseline_binding_and_both_lists_must_reproduce_exact_bytes(self):
        for path in (RENDER.BINDING, RENDER.PARENT, RENDER.HELPER):
            changed = dict(self.current); changed[path] += b" "
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "baseline derivation"):
                RENDER._derive_projection(self.source, self.inputs, changed)

    def test_source_and_all_retained_input_pins_are_mandatory(self):
        with self.assertRaisesRegex(ValueError, "source pin"):
            RENDER.proposed_derive_bytes(self.source + b"\n")
        with self.assertRaisesRegex(ValueError, "all five"):
            RENDER._decode_inputs({}, self.active)
        raw = {key: b"{}" for key in self.active["PINNED_INPUTS"]}
        with self.assertRaisesRegex(ValueError, "pinned derivation input changed"):
            RENDER._decode_inputs(raw, self.active)
        with self.assertRaisesRegex(ValueError, "assessment pin"):
            RENDER._validate_capture(b"{}", b"", {}, {})

    def test_hosted_tests_accept_only_exact_future_source_without_regranting(self):
        current = (BASE / "derive_read_policy.py").read_bytes()
        if RENDER.digest(current) in (IMAGE_REBOUND_DERIVE_SHA, LAZY_SUBAGENT_DERIVE_SHA):
            self.assertEqual(baseline_source(current), self.source)
            with self.assertRaisesRegex(ValueError, "neither exact"):
                baseline_source(current + b"\n")
            with self.assertRaisesRegex(ValueError, "source pin"):
                RENDER.proposed_derive_bytes(current)
        future = RENDER.proposed_derive_bytes(self.source)
        self.assertEqual(RENDER.digest(future), PROPOSED_DERIVE_SHA)
        self.assertEqual(baseline_source(future), self.source)
        with self.assertRaisesRegex(ValueError, "neither exact"):
            baseline_source(future + b"\n")
        # Production renderer remains original-only; the inverse is a test fixture.
        with self.assertRaisesRegex(ValueError, "source pin"):
            RENDER.proposed_derive_bytes(future)

    def test_exact_payload_layer_scope_and_unapplied_permission_are_enforced(self):
        proposal = json.loads((BASE / "proposal/openssl-read-proposal.json").read_bytes())
        payload = (BASE / "proposal/image-openssl.cnf").read_bytes()
        RENDER._validate_proposal(proposal, payload, self.active)
        for field, value in (("permission", "READ_DIRECTORY"), ("scopes", ["parent"]),
                             ("noDirectoryReadGrant", False), ("status", "APPLIED"),
                             ("completeDynamicClosureClaimed", True)):
            changed = copy.deepcopy(proposal); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                RENDER._validate_proposal(changed, payload, self.active)
        changed = copy.deepcopy(proposal); changed["savedLayerCustody"]["layerDiffId"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "saved-layer"):
            RENDER._validate_proposal(changed, payload, self.active)
        with self.assertRaisesRegex(ValueError, "payload"):
            RENDER._validate_proposal(proposal, payload + b"\n", self.active)

    def test_duplicate_json_keys_cannot_change_permission_semantics(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            RENDER.decode_json(b'{"permission":"READ_FILE","permission":"READ_DIRECTORY"}')

    def test_output_is_patch_only_separate_exclusive_and_never_active_files(self):
        files, _, _ = RENDER._derive_projection(self.source, self.inputs, self.current)
        patch = RENDER.standalone_patch({RENDER.DERIVE: self.source, **self.current}, files)
        self.assertEqual(patch.count(b"diff --git "), 4)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); checkout = root / "checkout"; checkout.mkdir()
            marker = checkout / "active"; marker.write_bytes(b"preserved")
            for destination in (checkout, checkout / "proposal"):
                with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "outside"):
                    RENDER.write_proposal_output(destination, checkout, patch, {"policyApplied": False})
            alias = root / "alias"; alias.symlink_to(checkout, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "outside"):
                RENDER.write_proposal_output(alias / "proposal", checkout, patch, {})
            output = root / "proposal"
            RENDER.write_proposal_output(output, checkout, patch, {"policyApplied": False})
            self.assertEqual(sorted(p.name for p in output.iterdir()),
                             ["openssl-read-proposal.patch", "projection.json"])
            self.assertEqual((output / "openssl-read-proposal.patch").read_bytes(), patch)
            self.assertFalse(json.loads((output / "projection.json").read_bytes())["policyApplied"])
            self.assertEqual(marker.read_bytes(), b"preserved")
            with self.assertRaises(FileExistsError):
                RENDER.write_proposal_output(output, checkout, patch, {})


if __name__ == "__main__":
    unittest.main()
