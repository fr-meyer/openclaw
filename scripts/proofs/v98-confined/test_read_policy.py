#!/usr/bin/env python3
"""Portable read-policy admission tests; no image execution or native probes.

These cases guard the real metadata-to-Landlock-list boundary and trusted
pre-start byte verifier. Attack inputs are synthetic files/metadata rather than
copies of the generated product inventory. The kernel enforcement proof belongs
to the separately authorized hosted executor, not these unit tests.
"""
import copy
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path, PurePosixPath

SPEC = importlib.util.spec_from_file_location("v98_read_policy", Path(__file__).with_name("derive_read_policy.py"))
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def file_row(path, data=b"x", mode="0o644"):
    return {"path": path, "mode": mode, "type": "file", "bytes": len(data), "sha256": POLICY.sha256_bytes(data)}


def directories_for(paths):
    return {str(parent): {"path": str(parent), "mode": "0o755", "type": "directory"}
            for path in paths for parent in PurePosixPath(path).parents if str(parent) != "/"}


def synthetic_derivation_inputs():
    paths = list(POLICY.APP_METADATA) + list(POLICY.SYSTEM_FILES) + [POLICY.GNU_FS_SAFE, POLICY.GNU_KOFFI, "/app/dist/doctor.mjs"]
    entries = directories_for(paths)
    entries.update({path: file_row(path) for path in paths})
    elf_entries = [dict(entries[path]) for path in (POLICY.GNU_FS_SAFE, POLICY.GNU_KOFFI) + POLICY.SYSTEM_FILES[:-1]]
    next(e for e in elf_entries if e["path"] == POLICY.NODE)["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
    return {
        "graph": {"schema": "openclaw-v98-static-import-graph/v1", "completeClosureClaimed": False,
                  "imageJavaScriptExecuted": False, "files": [dict(entries["/app/dist/doctor.mjs"])], "metadata": [], "unresolved": []},
        "inventory": {"schema": "openclaw-image-filesystem-inventory/v1", "entries": list(entries.values())},
        "catalog": {"schema": "openclaw-v98-independent-final-catalog-join/v1", "imageSha256": POLICY.IMAGE_SHA256,
                    "imageConfigId": POLICY.IMAGE_CONFIG, "inventorySha256": POLICY.PINNED_INPUTS["inventory"][1],
                    "runtimeExecuted": False, "differences": []},
        "classification": {"rawReceiptSha256": POLICY.PINNED_INPUTS["catalog"][1], "waiverOrExecutionAdmission": False},
        "elf": {"entries": elf_entries},
    }


class ReadPolicyTests(unittest.TestCase):
    def test_read_list_rejects_injection_relative_blank_and_duplicate_entries(self):
        bad = ["", "/", "app/module.mjs", "//app/module.mjs", "/app/../etc/passwd", "/app/a\n/etc/passwd", "/app/a\0b", "/app/a\rb", "/app/a\tb"]
        for path in bad:
            with self.subTest(path=repr(path)), self.assertRaises(ValueError):
                POLICY.read_list_bytes([path])
        with self.assertRaises(ValueError):
            POLICY.read_list_bytes(["/app/a", "/app/a"])
        self.assertEqual(POLICY.read_list_bytes(["/app/a", "/app/b"]), b"/app/a\n/app/b\n")

    def test_metadata_must_be_regular_files_not_directory_or_symlink_rules(self):
        for kind in ("directory", "symlink", "fifo", "character-device", "hardlink"):
            row = {**file_row("/app/selected"), "type": kind}
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                POLICY.regular_identity(row)
        for field, value in [("bytes", True), ("bytes", -1), ("sha256", "a" * 63), ("mode", "644")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                POLICY.regular_identity({**file_row("/app/selected"), field: value})

    def test_duplicate_catalog_paths_are_rejected_before_selection(self):
        row = file_row("/app/selected")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            POLICY.catalog_entries({"schema": "openclaw-image-filesystem-inventory/v1", "entries": [row, dict(row)]})

    def test_alias_grants_only_bound_regular_target(self):
        entries = {**directories_for(["/app/real/module.mjs"]), "/app/real/module.mjs": file_row("/app/real/module.mjs"),
                   "/alias": {"path": "/alias", "type": "symlink", "mode": "0o777", "target": "/app/real"}}
        bound, aliases = POLICY.bind_selected_paths({"/alias/module.mjs": {"selected"}}, entries, [])
        self.assertEqual(list(bound), ["/app/real/module.mjs"])
        self.assertEqual(aliases["/alias"]["target"], "/app/real")
        self.assertNotIn("/alias", bound)

    def test_alias_escape_loop_and_non_directory_ancestors_fail_closed(self):
        for target in ("../../outside", "/loop"):
            entries = {"/loop": {"path": "/loop", "type": "symlink", "mode": "0o777", "target": target}}
            with self.subTest(target=target), self.assertRaises(ValueError):
                POLICY.resolve_catalog_path("/loop", entries)
        with self.assertRaisesRegex(ValueError, "non-directory"):
            POLICY.resolve_catalog_path("/app/selected/child", {"/app": {"path": "/app", "type": "directory"},
                                       "/app/selected": file_row("/app/selected")})

    def test_selected_alias_or_target_catalog_difference_is_never_waived(self):
        entries = {**directories_for(["/app/target"]), "/app/target": file_row("/app/target"),
                   "/alias": {"path": "/alias", "type": "symlink", "mode": "0o777", "target": "/app/target"}}
        for changed in ("/alias", "/app/target"):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "saved-layer"):
                POLICY.bind_selected_paths({"/alias": {"selected"}}, entries, [{"path": changed}])

    def test_graph_identity_and_final_image_binding_cannot_drift(self):
        original = synthetic_derivation_inputs()
        for field, value in [("imageSha256", "0" * 64), ("imageConfigId", "sha256:" + "0" * 64), ("runtimeExecuted", True)]:
            altered = copy.deepcopy(original)
            altered["catalog"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "saved-layer"):
                POLICY.derive_binding(**altered)
        altered = copy.deepcopy(original)
        altered["graph"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "graph row"):
            POLICY.derive_binding(**altered)

    def test_unknown_selectors_get_no_new_permission_and_foreign_native_is_not_admitted(self):
        kind, _ = POLICY.classify_selector({"from": "/app/unknown.mjs", "expression": "require(userInput)", "kind": "computed-require"})
        self.assertEqual(kind, "UNKNOWN_FORBIDDEN")
        row = {"from": "/app/node_modules/.pnpm/koffi@3.3.1/node_modules/koffi/src/koffi/src/static.cjs", "specifier": "@koromix/koffi-linux-x64"}
        with self.assertRaisesRegex(ValueError, "required Koffi"):
            POLICY.classify_selector(row)
        binding = POLICY.derive_binding(**synthetic_derivation_inputs())
        paths = POLICY.image_read_paths(binding)
        self.assertIn(POLICY.GNU_FS_SAFE, paths)
        self.assertIn(POLICY.GNU_KOFFI, paths)
        self.assertFalse(any("musl_x64" in p for p in paths))
        self.assertFalse(binding["completeImportClosureClaimed"])

    def test_mounted_regular_file_hash_size_and_mode_are_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app").mkdir()
            path = root / "app/module.mjs"
            path.write_bytes(b"module")
            path.chmod(0o644)
            row = file_row("/app/module.mjs", b"module")
            POLICY.verify_regular_files(root, [row])
            path.write_bytes(b"alter!")
            with self.assertRaisesRegex(ValueError, "bytes changed"):
                POLICY.verify_regular_files(root, [row])
            path.write_bytes(b"module")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "type/size/mode"):
                POLICY.verify_regular_files(root, [row])

    def test_mounted_symlink_prefix_and_root_redirection_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "root"
            other = base / "other"
            root.mkdir()
            other.mkdir()
            (other / "module.mjs").write_bytes(b"module")
            (other / "module.mjs").chmod(0o644)
            (root / "app").symlink_to(other, target_is_directory=True)
            with self.assertRaises(OSError):
                POLICY.verify_regular_files(root, [file_row("/app/module.mjs", b"module")])
            alias_root = base / "alias-root"
            alias_root.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                POLICY.verify_regular_files(alias_root, [])

    def test_mounted_fifo_rejected_without_open_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app").mkdir()
            os.mkfifo(root / "app/module.mjs", 0o644)
            with self.assertRaisesRegex(ValueError, "type/size/mode"):
                POLICY.verify_regular_files(root, [file_row("/app/module.mjs", b"")])

    def test_namespace_alias_target_and_directory_type_are_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app").mkdir(mode=0o755)
            (root / "alias").symlink_to("app", target_is_directory=True)
            alias_mode = oct(stat.S_IMODE((root / "alias").lstat().st_mode))
            rows = [{"path": "/app", "mode": "0o755", "type": "directory"},
                    {"path": "/alias", "mode": alias_mode, "type": "symlink", "target": "app"}]
            POLICY.verify_namespace(root, rows)
            (root / "alias").unlink()
            (root / "alias").symlink_to("outside", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "alias changed"):
                POLICY.verify_namespace(root, rows)

    def test_reviewed_binding_hash_is_mandatory_and_tampering_is_rejected(self):
        binding = POLICY.derive_binding(**synthetic_derivation_inputs())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "binding.json"
            data = json.dumps(binding).encode()
            path.write_bytes(data)
            POLICY.read_bound_policy(path, POLICY.sha256_bytes(data))
            with self.assertRaisesRegex(ValueError, "digest is required"):
                POLICY.read_bound_policy(path, "")
            path.write_bytes(data + b" ")
            with self.assertRaisesRegex(ValueError, "binding changed"):
                POLICY.read_bound_policy(path, POLICY.sha256_bytes(data))


if __name__ == "__main__":
    unittest.main()
