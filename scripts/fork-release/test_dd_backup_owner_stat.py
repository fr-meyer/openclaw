"""The final-image backup identity check uses metadata only as data owner."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import gcp_snapshot_trial as trial
import release


class BackupOwnerStatTests(unittest.TestCase):
    def setUp(self):
        self.paths = [f"/mnt/synthetic-clone/backups/db{i}.bak" for i in range(11)]
        self.rows = [{"device": 2065, "inode": i + 100, "links": 1,
                      "sizeBytes": 4096, "allocatedBytes": 4096,
                      "modifiedNs": 123, "changedNs": 456,
                      "ownerUid": 1000, "mode": 0o600} for i in range(11)]

    def test_exact_owner_command_and_metadata_only_request(self):
        payload = trial.durable.encode(self.rows)
        with patch.object(trial.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, payload, b"")) as run:
            self.assertEqual(trial.backup_owner_stats(self.paths), self.rows)
        args, kwargs = run.call_args
        self.assertEqual(args[0][:7], ["/usr/bin/sudo", "-n", "-u", "frmeyer", "--",
                                       "/usr/bin/env", "-i"])
        self.assertEqual(args[0][-5:-2], ["-I", "-B", "-S"])
        self.assertEqual(args[0][-2], "-c")
        self.assertIn("file.lstat()", args[0][-1])
        self.assertNotIn("read_bytes()", args[0][-1])
        self.assertEqual(json.loads(kwargs["input"]), {
            "schema": "openclaw.backup-owner-stat.v1", "paths": self.paths})
        self.assertEqual(kwargs["timeout"], 15)

    def test_refuses_missing_duplicate_failed_or_malformed_metadata(self):
        with self.assertRaises(release.Refusal):
            trial.backup_owner_stats(self.paths[:-1])
        with self.assertRaises(release.Refusal):
            trial.backup_owner_stats(self.paths[:-1] + self.paths[:1])
        for result in (subprocess.CompletedProcess([], 1, b"", b"denied"),
                       subprocess.CompletedProcess([], 0, b"[]", b""),
                       subprocess.CompletedProcess([], 0, b"not-json", b"")):
            with self.subTest(result=result.returncode), patch.object(
                    trial.subprocess, "run", return_value=result), self.assertRaises(release.Refusal):
                trial.backup_owner_stats(self.paths)

    def test_embedded_stat_script_reads_synthetic_file_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(11):
                file = Path(directory).resolve() / f"backup-{index}.bak"
                file.write_bytes(b"synthetic-metadata-only")
                paths.append(str(file))
            request = trial.durable.encode({"schema": "openclaw.backup-owner-stat.v1",
                                            "paths": paths})
            identity_guard = ("if os.getuid() != 1000 or os.geteuid() != 1000:\n"
                              "    raise SystemExit(2)\n")
            self.assertIn(identity_guard, trial._BACKUP_OWNER_STAT_SCRIPT)
            # macOS local fixture cannot assume the VM's existing UID 1000.
            local_script = trial._BACKUP_OWNER_STAT_SCRIPT.replace(identity_guard, "", 1)
            result = subprocess.run([sys.executable, "-I", "-B", "-S", "-c",
                                     local_script], input=request,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            rows = json.loads(result.stdout)
            self.assertEqual(len(rows), 11)
            self.assertEqual([row["inode"] for row in rows],
                             [(Path(path).stat().st_ino) for path in paths])

    def test_comparison_rejects_changed_backup_identity(self):
        backup_id = trial.DD_BACKUP_ID
        paths = sorted(f"/mnt/synthetic-clone/backups/db{i}.pre-startup-migration-{backup_id}.bak"
                       for i in range(11))
        original = [{"path": path, **row} for path, row in zip(paths, self.rows)]
        artifacts = [{**row, "kind": "migration-backup",
                      "classification": "native-revalidation-required", "disposition": "retain",
                      "nativeDiscardOnRetry": False} for row in original]
        manifest = "c" * 64
        prior = {"clean": {"mountRoot": "/mnt/synthetic-clone"},
                 "check": {"reconciliation": {"artifacts": artifacts}}}
        receipt = {"backupId": backup_id, "backupManifestSha256": manifest,
                   "backupFiles": original}
        reuse = {"backupId": backup_id, "backupCount": 11, "manifestSha256": manifest,
                 "targetSourceSha": trial.LEASE_PATCH_IMAGE["sourceSha"],
                 "targetImageReceiptSha256": trial.LEASE_PATCH_RECEIPT_SHA256}
        with patch.object(trial, "backup_reuse", return_value=reuse), patch.object(
                trial, "backup_owner_stats", return_value=self.rows):
            trial.validate_dd_original_backup_files(prior, receipt)
            changed = [dict(row) for row in self.rows]
            changed[4]["inode"] += 1
            with patch.object(trial, "backup_owner_stats", return_value=changed), \
                    self.assertRaisesRegex(release.Refusal, "trial.dd_final.backup_changed"):
                trial.validate_dd_original_backup_files(prior, receipt)


if __name__ == "__main__":
    unittest.main()
