"""Inert descriptor/sampling contracts; no mount, Docker or database execution."""
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("v98_usage_host", Path(__file__).with_name("host-runtime.py"))
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


def counters(allocated=4096):
    return {"capacityBytes": HOST.MAX_SCRATCH, "allocatedBytes": allocated,
            "availableBytes": HOST.MAX_SCRATCH-allocated, "usedInodes": 3, "freeInodes": 100}


class ScratchUsageTests(unittest.TestCase):
    def descriptor(self, identity=(2, 3), blocks=4096, free=4095):
        info = SimpleNamespace(st_dev=identity[0], st_ino=identity[1], st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_gid=1000)
        usage = SimpleNamespace(f_frsize=4096, f_bsize=4096, f_blocks=blocks, f_bfree=free, f_bavail=free, f_files=103, f_ffree=100)
        return info, usage

    def test_exact_inode_descriptor_and_allocated_bytes_include_unlinked_usage(self):
        info, usage = self.descriptor()
        with patch.object(HOST.os, "open", return_value=19) as opened, patch.object(HOST.os, "fstat", return_value=info), \
             patch.object(HOST.os, "fstatvfs", return_value=usage) as observed, patch.object(HOST.os, "close") as closed:
            self.assertEqual(HOST.observe_scratch_usage("scratch", (2, 3)), counters())
            self.assertEqual(opened.call_args.args[1], HOST.os.O_RDONLY | HOST.os.O_DIRECTORY | HOST.os.O_NOFOLLOW)
            observed.assert_called_once_with(19); closed.assert_called_once_with(19)

    def test_wrong_inode_or_capacity_or_counter_refuses_and_closes(self):
        for identity, blocks, free in [((7, 3), 4096, 4095), ((2, 3), 8192, 4095), ((2, 3), 4096, 4097)]:
            info, usage = self.descriptor(identity, blocks, free)
            with self.subTest(identity=identity, blocks=blocks, free=free), \
                 patch.object(HOST.os, "open", return_value=19), patch.object(HOST.os, "fstat", return_value=info), \
                 patch.object(HOST.os, "fstatvfs", return_value=usage), patch.object(HOST.os, "close") as closed:
                with self.assertRaises(HOST.Refusal): HOST.observe_scratch_usage("scratch", (2, 3))
                closed.assert_called_once_with(19)

    def test_periodic_sampling_is_throttled_and_reports_observed_gap(self):
        with patch.object(HOST.time, "monotonic", return_value=0) as clock, \
             patch.object(HOST, "observe_scratch_usage", return_value=counters()) as observed:
            sampler = HOST.ScratchUsage("scratch", (2, 3))
            sampler.observe(b"")
            clock.return_value = 0.01; sampler.observe(b"")
            self.assertEqual(observed.call_count, 1)
            clock.return_value = 0.08; sampler.observe(b"")
            self.assertEqual(observed.call_count, 2)
            self.assertEqual(sampler.max_gap, 0.08)

    def test_partial_line_is_not_consumed_and_complete_boundary_is_observed_once(self):
        line = b'{"event":"phase_started","phase":1}\n'
        with patch.object(HOST.time, "monotonic", return_value=0), patch.object(HOST, "observe_scratch_usage", return_value=counters()):
            sampler = HOST.ScratchUsage("scratch", (2, 3))
            sampler.observe(line[:-1]); self.assertEqual(sampler.offset, 0)
            sampler.observe(line); sampler.observe(line)
            self.assertEqual(len(sampler.boundaries), 1)
            self.assertEqual(sampler.phase, 1)

    def test_all_six_received_boundaries_retained_with_explicit_peak_limits(self):
        lines = b"".join((json.dumps({"event": event, "phase": phase}) + "\n").encode()
                         for phase in range(1, 7) for event in ("phase_started", "phase_joined"))
        with tempfile.TemporaryDirectory() as temp, patch.object(HOST.time, "monotonic", return_value=1), \
             patch.object(HOST, "observe_scratch_usage", return_value=counters(8192)):
            sampler = HOST.ScratchUsage("scratch", (2, 3)); sampler.observe(lines)
            target = Path(temp) / "usage.json"; receipt = sampler.seal(target)
            result = json.loads(target.read_text())
            self.assertEqual(set(result["nativeEventCorrelatedWindows"]), set("123456"))
            self.assertEqual(len(result["nativeEventReceiptObservations"]), 12)
            self.assertEqual(result["maximumSampledAllocatedBytes"], 8192)
            self.assertIn("LOWER_BOUND", result["status"])
            self.assertIn("may lag execution", result["limitations"])
            self.assertFalse(receipt["exactPeakClaimed"])
            self.assertLess(receipt["bytes"], 32 * 1024)

    def test_invalid_trusted_phase_and_unbounded_boundaries_refuse(self):
        with patch.object(HOST.time, "monotonic", return_value=0), patch.object(HOST, "observe_scratch_usage", return_value=counters()):
            for line in [b'{bad}\n', b'{"event":"phase_started","phase":7}\n']:
                sampler = HOST.ScratchUsage("scratch", (2, 3))
                with self.assertRaises(HOST.Refusal): sampler.observe(line)
            sampler = HOST.ScratchUsage("scratch", (2, 3))
            with self.assertRaisesRegex(HOST.Refusal, "boundary budget"):
                sampler.observe(b'{"event":"phase_started","phase":1}\n' * 21)


if __name__ == "__main__":
    unittest.main()
