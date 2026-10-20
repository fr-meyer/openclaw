import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
SCRIPT = HERE / "verify-image-plugins.mjs"


class ImagePluginPayloadTests(unittest.TestCase):
    def test_codex_payload_requires_compiled_entry_and_matching_doctor_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"version": "2026.10.5"}))
            codex = root / "extensions" / "codex"
            codex.mkdir(parents=True)
            package = {
                "name": "@openclaw/codex", "version": "2026.10.5",
                "openclaw": {"extensions": ["./index.ts"],
                             "compat": {"pluginApi": ">=2026.10.5"},
                             "build": {"openclawVersion": "2026.10.5"}},
            }
            descriptor = {
                "id": "codex", "providers": ["codex"],
                "doctorContract": {"configRepair": True,
                                   "stateMigrations": [{"id": "codex-migration"}]},
            }
            (codex / "package.json").write_text(json.dumps(package))
            (codex / "openclaw.plugin.json").write_text(json.dumps(descriptor))
            entry = root / "dist" / "extensions" / "codex" / "index.js"
            entry.parent.mkdir(parents=True)
            entry.write_text("export default {};\n")

            def inspect():
                return subprocess.run(["node", str(SCRIPT), str(root), "codex", "2026.10.5"],
                                      capture_output=True, text=True)

            result = inspect()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [
                {"id": "codex", "package": "@openclaw/codex", "version": "2026.10.5"}])

            entry.unlink()
            missing = inspect()
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("index.js", missing.stderr)

            entry.write_text("export default {};\n")
            package["version"] = "2026.9.6"
            (codex / "package.json").write_text(json.dumps(package))
            stale = inspect()
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("does not match the image host", stale.stderr)


if __name__ == "__main__":
    unittest.main()
