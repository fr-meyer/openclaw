import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class PacketAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.packet = json.loads((ROOT / "packet.json").read_text())
        self.validate = module("validate-packet").validate

    def test_original_stays_blocked(self):
        self.assertIn("NO_RUNTIME_ADMISSION", self.validate(self.packet)["status"])

    def test_approval_stamp_cannot_admit_execution(self):
        self.packet["status"] = "REVIEWED_EXECUTION_PACKET"
        with self.assertRaisesRegex(ValueError, "runtime admission"):
            self.validate(self.packet)

    def test_changed_doctor_source_cut_rejected(self):
        self.packet["doctor"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Doctor binding"):
            self.validate(self.packet)

    def test_changed_artifact_binding_rejected(self):
        self.packet["artifact"]["imageSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "frozen manifest identity"):
            self.validate(self.packet)

    def test_changed_critical_chain_binding_rejected(self):
        self.packet["criticalChain"][3]["imageSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "frozen manifest identity"):
            self.validate(self.packet)

    def test_missing_required_scratch_env_rejected(self):
        del self.packet["commandContext"]["requiredGlobalEnvironment"]["PARITY_FIXTURE_SCRATCH_ROOT"]
        with self.assertRaisesRegex(ValueError, "scratch environment"):
            self.validate(self.packet)

    def test_reordered_migration_and_restore_rejected(self):
        self.packet["phases"][2], self.packet["phases"][4] = self.packet["phases"][4], self.packet["phases"][2]
        with self.assertRaisesRegex(ValueError, "phase manifest"):
            self.validate(self.packet)

    def test_child_permission_change_rejected(self):
        self.packet["blockedRequirement"]["childCreation"] = "ALLOWED"
        with self.assertRaisesRegex(ValueError, "child boundary"):
            self.validate(self.packet)

    def test_tampered_input_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "fixture.mjs").write_text("throw Error('do not execute');")
            with self.assertRaisesRegex(ValueError, "input bytes changed"):
                self.validate(self.packet, p)


class StaticReaderTests(unittest.TestCase):
    def test_changed_image_rejected_before_storage(self):
        read = module("read-closure-bytes").read
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "image.tar.gz").write_bytes(b"inert unauthenticated archive")
            with self.assertRaisesRegex(ValueError, "admitted input changed"):
                read(p, p / "objects")
            self.assertFalse((p / "objects").exists())

    def test_unreviewed_python_not_executed(self):
        join = module("full-catalog-join").join
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            tool = p / "untrusted.py"
            marker = p / "marker"
            tool.write_text("open(" + repr(str(marker)) + ", 'w').write('executed')")
            with self.assertRaisesRegex(ValueError, "pinned proof input"):
                join(p, tool)
            self.assertFalse(marker.exists())


class ElfDataTests(unittest.TestCase):
    def setUp(self):
        self.elf = module("elf-dependencies").elf

    def header(self):
        b = bytearray(64)
        b[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", b, 18, 62)
        struct.pack_into("<Q", b, 32, 64)
        struct.pack_into("<HH", b, 54, 56, 0)
        return b

    def test_inert_header_has_no_dependencies(self):
        self.assertEqual(self.elf(self.header())["needed"], [])

    def test_wrong_architecture_rejected(self):
        b = self.header()
        struct.pack_into("<H", b, 18, 183)
        with self.assertRaisesRegex(ValueError, "x86-64"):
            self.elf(b)

    def test_truncated_program_header_rejected(self):
        b = self.header()
        struct.pack_into("<H", b, 56, 1)
        with self.assertRaisesRegex(ValueError, "program-header"):
            self.elf(b)

    def test_nonterminated_interpreter_rejected(self):
        b = self.header()
        struct.pack_into("<H", b, 56, 1)
        b.extend(struct.pack("<IIQQQQQQ", 3, 0, 120, 0, 0, 3, 3, 1))
        b.extend(b"bad")
        with self.assertRaisesRegex(ValueError, "interpreter"):
            self.elf(b)


if __name__ == "__main__":
    unittest.main()
