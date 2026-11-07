import copy
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import manifest_capture as c

HERE = Path(__file__).resolve().parent


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="manifest-capture-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "source"
        self.root.mkdir()
        self.out = Path(self.temp.name).resolve() / "private"
        self.originals = {name: (HERE / "public-originals" / f"{name}.json").read_bytes()
                          for name in c.PLUGIN_PATHS}
        for name, path in c.PLUGIN_PATHS.items():
            target = self.root / path
            target.parent.mkdir(parents=True)
            target.write_bytes(self.originals[name])
            target.chmod(0o644)

    def generated(self, plugin="workboard", styles=True):
        value = json.loads(self.originals[plugin])
        value["controlUi"] = {"entry": "dist/control-ui/" + "a" * 64 + "/index.js"}
        if styles:
            value["controlUi"]["styles"] = ["dist/control-ui/" + "a" * 64 + "/index.css"]
        return c._encode(value)

    def after(self, raw=None, paths=None):
        c.capture_before(self.root, self.out)
        (self.root / c.PLUGIN_PATHS["workboard"]).write_bytes(raw or self.generated())
        c.capture_after(self.root, self.out, paths or [c.PLUGIN_PATHS["workboard"]])

    def test_pinned_public_originals_and_serialization(self):
        for name, raw in self.originals.items():
            self.assertEqual(c._digest(raw), c.ORIGINAL_SHA256[name])
            self.assertEqual(c._encode(json.loads(raw)), raw)
            self.assertFalse(c.validate_pair(raw, raw, name)["changed"])

    def test_valid_generated_pointers_produce_only_five_bounded_files(self):
        self.after()
        result = c.adjudicate(self.out)
        self.assertFalse(result["assetContentAuthenticated"])
        self.assertFalse(result["qualified"])
        public = self.out / "validated-payload"
        self.assertEqual(sorted(p.name for p in public.iterdir()),
                         ["manifest-capture-receipt.json", "workboard.after.json", "workboard.diff",
                          "x.after.json", "x.diff"])
        self.assertLess(sum(p.stat().st_size for p in self.out.rglob("*") if p.is_file()),
                        c.MAX_PUBLIC_BYTES)
        for p in self.out.rglob("*"):
            if p.is_file():
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_optional_css_absent_is_valid_builder_shape(self):
        self.assertTrue(c.validate_pair(self.originals["workboard"],
                                       self.generated(styles=False), "workboard")["changed"])

    def test_outside_field_change_is_rejected_and_raw_remains_private(self):
        value = json.loads(self.generated())
        value["description"] = "arbitrary new text"
        raw = c._encode(value)
        self.after(raw)
        with self.assertRaisesRegex(c.Refusal, "outside_or_serialization"):
            c.adjudicate(self.out)
        self.assertEqual((self.out / "after.workboard.raw.json").read_bytes(), raw)
        self.assertFalse((self.out / "validated-payload").exists())

    def test_unknown_control_key_rejected(self):
        value = json.loads(self.generated())
        value["controlUi"]["url"] = "https://invalid.example/"
        with self.assertRaisesRegex(c.Refusal, "control_shape"):
            c.validate_pair(self.originals["workboard"], c._encode(value), "workboard")

    def test_urls_traversal_uppercase_short_hash_and_wrong_filename_rejected(self):
        for entry in ["https://example.invalid/index.js", "../index.js",
                      "dist/control-ui/" + "A" * 64 + "/index.js",
                      "dist/control-ui/abc/index.js",
                      "dist/control-ui/" + "a" * 64 + "/other.js"]:
            with self.subTest(entry=entry):
                value = json.loads(self.generated())
                value["controlUi"]["entry"] = entry
                with self.assertRaisesRegex(c.Refusal, "manifest.entry"):
                    c.validate_pair(self.originals["workboard"], c._encode(value), "workboard")

    def test_unsupported_control_types_and_styles_rejected(self):
        for control in [None, [], {"entry": False}, {"entry": "dist/control-ui/" + "a" * 64 + "/index.js",
                                                      "styles": []},
                        {"entry": "dist/control-ui/" + "a" * 64 + "/index.js",
                         "styles": ["dist/control-ui/" + "b" * 64 + "/index.css"]}]:
            value = json.loads(self.generated())
            value["controlUi"] = control
            with self.assertRaises(c.Refusal):
                c.validate_pair(self.originals["workboard"], c._encode(value), "workboard")

    def test_duplicate_key_and_nonjson_constant_rejected(self):
        for raw in [b'{"controlUi":{},"controlUi":{}}', b'{"controlUi":NaN}']:
            with self.assertRaises(c.Refusal):
                c.validate_pair(self.originals["workboard"], raw, "workboard")

    def test_whitespace_and_unknown_root_keys_rejected(self):
        for raw in [self.generated() + b" ", c._encode({**json.loads(self.generated()), "token": "no"})]:
            with self.assertRaisesRegex(c.Refusal, "outside_or_serialization"):
                c.validate_pair(self.originals["workboard"], raw, "workboard")

    def test_wrong_before_pin_preserved_then_refused(self):
        wrong = self.originals["workboard"] + b" "
        (self.root / c.PLUGIN_PATHS["workboard"]).write_bytes(wrong)
        with self.assertRaisesRegex(c.Refusal, "before_pin"):
            c.capture_before(self.root, self.out)
        self.assertEqual((self.out / "before.workboard.raw.json").read_bytes(), wrong)

    def test_symlink_and_hardlink_source_refused(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                p = self.root / c.PLUGIN_PATHS["workboard"]
                backup = self.root / (kind + ".json")
                p.rename(backup)
                if kind == "symlink":
                    p.symlink_to(backup)
                else:
                    os.link(backup, p)
                out = self.out.with_name(kind)
                with self.assertRaisesRegex(c.Refusal, "capture_refused"):
                    c.capture_before(self.root, out)
                p.unlink()
                backup.rename(p)

    def test_oversized_prefix_preserved_without_publication(self):
        c.capture_before(self.root, self.out)
        (self.root / c.PLUGIN_PATHS["workboard"]).write_bytes(b"x" * (c.MAX_FILE_BYTES + 10))
        with self.assertRaisesRegex(c.Refusal, "capture_refused"):
            c.capture_after(self.root, self.out, [c.PLUGIN_PATHS["workboard"]])
        self.assertEqual((self.out / "after.workboard.raw.json").stat().st_size, c.MAX_FILE_BYTES)
        self.assertFalse(json.loads((self.out / "after.custody.json").read_bytes())["files"]["workboard"]["complete"])

    def test_unknown_or_duplicate_changed_paths_are_metadata_only(self):
        c.capture_before(self.root, self.out)
        for paths in [[], ["package.json"], [c.PLUGIN_PATHS["workboard"]] * 2]:
            with self.assertRaisesRegex(c.Refusal, "changed_paths_not_fixed"):
                c.capture_after(self.root, self.out, paths)
        self.assertFalse((self.out / "after.workboard.raw.json").exists())

    def test_snapshot_tamper_refused(self):
        self.after()
        (self.out / "after.workboard.raw.json").write_bytes(self.generated(styles=False))
        with self.assertRaisesRegex(c.Refusal, "snapshot_pin"):
            c.adjudicate(self.out)

    def test_observed_change_set_must_match_validated_byte_changes(self):
        self.after(paths=list(c.PLUGIN_PATHS.values()))
        with self.assertRaisesRegex(c.Refusal, "change_selection_mismatch"):
            c.adjudicate(self.out)

    def test_capture_is_once_only_and_source_unchanged_by_validator(self):
        self.after()
        current = (self.root / c.PLUGIN_PATHS["workboard"]).read_bytes()
        c.adjudicate(self.out)
        with self.assertRaisesRegex(c.Refusal, "custody.io_refused"):
            c.adjudicate(self.out)
        self.assertEqual((self.root / c.PLUGIN_PATHS["workboard"]).read_bytes(), current)
        with self.assertRaisesRegex(c.Refusal, "custody.io_refused"):
            c.capture_before(self.root, self.out)

    def replaced_during_read(self, target, symlink=False):
        original_read = os.read
        swapped = False

        def read_then_replace(fd, count):
            nonlocal swapped
            raw = original_read(fd, count)
            if raw and not swapped:
                swapped = True
                backup = target.with_name(target.name + "-opened-original")
                target.rename(backup)
                if symlink:
                    target.symlink_to(backup, target_is_directory=True)
                else:
                    shutil.copytree(backup, target)
            return raw

        with mock.patch.object(c.os, "read", side_effect=read_then_replace):
            with self.assertRaisesRegex(c.Refusal, "custody.capture_refused"):
                c.capture_before(self.root, self.out)
        record = json.loads((self.out / "before.custody.json").read_bytes())["files"]["workboard"]
        self.assertTrue(record["captured"])
        self.assertTrue(record["leafStable"])
        self.assertFalse(record["namedPathStable"])
        self.assertFalse(record["stable"])
        self.assertEqual((self.out / "before.workboard.raw.json").read_bytes(),
                         self.originals["workboard"])
        self.assertFalse((self.out / "validated-payload").exists())

    def test_replaced_plugin_parent_preserves_raw_then_refuses(self):
        self.replaced_during_read(self.root / "extensions/workboard")

    def test_replaced_source_root_preserves_raw_then_refuses(self):
        self.replaced_during_read(self.root)

    def test_replaced_parent_symlink_preserves_raw_then_refuses(self):
        self.replaced_during_read(self.root / "extensions/workboard", symlink=True)

    def test_public_custody_io_errors_are_safe_without_native_context(self):
        c.capture_before(self.root, self.out)
        calls = [lambda: c.capture_before(self.root, self.out),
                 lambda: c.capture_after(self.root, self.out / "missing-private",
                                         [c.PLUGIN_PATHS["workboard"]]),
                 lambda: c.adjudicate(self.out / "missing-private")]
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(c.Refusal) as caught:
                    call()
                self.assertEqual(str(caught.exception), "custody.io_refused")
                self.assertNotIn(str(self.out), str(caught.exception))
                self.assertIsNone(caught.exception.__context__)

    def test_private_write_error_is_safe_and_does_not_become_success(self):
        with mock.patch.object(c.os, "fsync", side_effect=PermissionError("private/path")):
            with self.assertRaises(c.Refusal) as caught:
                c.capture_before(self.root, self.out)
        self.assertEqual(caught.exception.code, "custody.io_refused")
        self.assertIsNone(caught.exception.__context__)
        self.assertTrue((self.out / "before.workboard.raw.json").exists())
        self.assertFalse((self.out / "validated-payload").exists())


if __name__ == "__main__":
    unittest.main()
