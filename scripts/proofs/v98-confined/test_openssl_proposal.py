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
FIXTURE_SIZING_DERIVE_SHA = "bb6070545fbd046aecab1ed8ddb1037dd1da5c6d6aa07ea517eeaae1c1ae40b3"
FIXTURE_SIZING_SHA = "29da5d15bcf2372771b283f4a838b3734113e6ca60f077a140d6b4edca642155"


def baseline_source(raw):
    """Test fixture only: accept exactly the original or exact projected source."""
    if RENDER.digest(raw) == FIXTURE_SIZING_DERIVE_SHA:
        pin = '"/proof/inputs/fixture.mjs": "'
        text = raw.decode("utf-8")
        if text.count(pin + FIXTURE_SIZING_SHA) != 1:
            raise ValueError("fixture pin inverse anchor changed")
        raw = text.replace(pin + FIXTURE_SIZING_SHA, pin + "777936fa311d3b6fb141dff1fc67f46e2cfddf0651bf75b30ae62f74368f674e").encode("utf-8")
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
