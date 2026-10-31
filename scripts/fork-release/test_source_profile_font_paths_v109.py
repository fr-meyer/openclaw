"""Literal-path/native-Git metadata tests, never an application or remote read.

Git writes are confined to a disposable synthetic repository owned by each test.
The full actual H-tree regression is a separate local receipt, not a 5MiB
published fixture or a claim that synthetic bytes are the candidate source.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest

import source_profile_diagnostic_v109 as diagnostic

FONTS = (
    "apps/ios/Sources/Fonts/Inter-Italic[opsz,wght].ttf",
    "apps/ios/Sources/Fonts/Inter[opsz,wght].ttf",
    "apps/ios/Sources/Fonts/RedHatDisplay[wght].ttf",
)
WORKBOARD = "extensions/workboard/openclaw.plugin.json"
TEXT_STATUS_SHA256 = "08480a3628ccd044d14a97c63ed24c94ea7cb177080cdeae53598a2c3720a975"
NUL_STATUS_SHA256 = "4f7c9394d465db69748be1cc1570518e6a8e9356bf427617c204713a3b91356e"


class NativeFixture:
    def __init__(self, root):
        self.root = root
        self.calls, self.facts = [], []
        self.env = {"PATH": os.environ["PATH"], "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_AUTHOR_NAME": "Synthetic Metadata Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic Metadata Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2026-10-30T00:00:00Z", "GIT_COMMITTER_DATE": "2026-10-30T00:00:00Z"}

    def git(self, *args):
        self.calls.append(args)
        argv = ["git", "-C", str(self.root), "-c", "protocol.allow=never", "-c", "credential.helper=",
            "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "core.fsmonitor=false",
            "-c", "core.useReplaceRefs=false", "-c", "maintenance.auto=0", "-c", "gc.auto=0", *args]
        child = subprocess.run(argv, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False)
        # Hash observations before checking return/cap. Never surface raw Git
        # errors or synthetic private paths in a test failure message.
        self.facts.append({"returncode": child.returncode, "stdoutBytes": len(child.stdout),
            "stdoutSha256": hashlib.sha256(child.stdout).hexdigest(), "stderrBytes": len(child.stderr),
            "stderrSha256": hashlib.sha256(child.stderr).hexdigest()})
        if child.returncode != 0 or len(child.stdout) > 8 * 1024 * 1024 or len(child.stderr) > 65536:
            raise AssertionError("native_metadata_fixture_git_refused")
        return child.stdout

    def seed(self):
        self.git("init", "--quiet", "--initial-branch=fixture", "--object-format=sha1", "--template=")
        for path in FONTS + (WORKBOARD,):
            p = self.root / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'{"synthetic":"before"}\n' if path == WORKBOARD else b"synthetic font bytes\n")
            p.chmod(0o644)
        self.git("add", "--", ".")
        self.git("commit", "--quiet", "-m", "synthetic native metadata fixture")
        return {"sourceSha": self.git("rev-parse", "HEAD").strip().decode("ascii"),
            "sourceTree": self.git("rev-parse", "HEAD^{tree}").strip().decode("ascii")}


class FontPathTests(unittest.TestCase):
    def test_only_three_literal_punctuation_characters_were_added(self):
        raw = Path(diagnostic.__file__).read_bytes()
        new = rb'[A-Za-z0-9_.@+ /,\[\]-]+'
        old = rb'[A-Za-z0-9_.@+ /-]+'
        self.assertEqual(raw.count(new), 1)
        self.assertEqual(hashlib.sha256(raw.replace(new, old, 1)).hexdigest(),
            "179c4adec0a76c1cd68fc2814a5cf066ed0e94bd33d6fe233b54dcb60fee22a3")
        for path in FONTS:
            self.assertEqual(diagnostic.safe_path(path.encode("ascii")), path)

    def test_controls_unicode_traversal_and_shell_alphabets_remain_refused(self):
        for value in (b"../x", b"/x", b"x/../y", b"x/./y", b"x//y", b"x/", b"x\x00y", b"x\ny",
            b"x\ry", b"x\ty", b"x\x1by", b"x\\y", b"x*", b"x?", b"x$()", b"x`y`", b"x{y}",
            "x/é".encode(), b"x/\xff"):
            with self.subTest(value=value), self.assertRaises(diagnostic.Unavailable):
                diagnostic.safe_path(value)

    def test_all_ASCII_changes_are_exactly_brackets_and_comma(self):
        old = re.compile(rb"[A-Za-z0-9_.@+ /-]+")
        changed = []
        for code in range(128):
            value = b"path/a" + bytes((code,)) + b"b"
            before = old.fullmatch(value) is not None
            try:
                diagnostic.safe_path(value)
                after = True
            except diagnostic.Unavailable:
                after = False
            if before != after:
                changed.append(code)
        self.assertEqual(changed, [44, 91, 93])

    def test_newly_valid_literal_paths_still_require_bound_tree_membership(self):
        raw = b" M apps/ios/Sources/Fonts/Unknown[opsz,wght].ttf\0"
        rows, unknown = diagnostic.status_entries(raw, {WORKBOARD: {}})
        self.assertEqual(rows, {})
        self.assertEqual(unknown, 1)

    def test_status_literal_hashes_match_complete_native_facts(self):
        status = (" M " + WORKBOARD + "\n").encode("ascii")
        nul = status[:-1] + b"\0"
        self.assertEqual(len(status), 45)
        self.assertEqual(hashlib.sha256(status).hexdigest(), TEXT_STATUS_SHA256)
        self.assertEqual(hashlib.sha256(nul).hexdigest(), NUL_STATUS_SHA256)
        rows, unknown = diagnostic.status_entries(nul, {WORKBOARD: {}})
        self.assertEqual(rows, {WORKBOARD: {"statusCode": " M", "pathRole": "path"}})
        self.assertEqual(unknown, 0)

    def test_native_Git_tree_with_all_fonts_and_dirty_Workboard_is_not_dropped(self):
        self.assertIsNotNone(shutil.which("git"), "native_git_required_for_metadata_regression")
        with tempfile.TemporaryDirectory(prefix="v109-font-native-") as temporary:
            root = Path(temporary).resolve()
            fixture = NativeFixture(root)
            source = fixture.seed()
            raw = fixture.git("ls-tree", "-rz", "--full-tree", source["sourceSha"])
            entries = diagnostic.tree_entries(raw)
            self.assertEqual(set(entries), set(FONTS + (WORKBOARD,)))
            (root / WORKBOARD).write_bytes(b'{"synthetic":"after"}\n')
            observed = {"head": fixture.git("rev-parse", "HEAD"), "tree": fixture.git("rev-parse", "HEAD^{tree}"),
                "status": fixture.git("status", "--porcelain=v1", "--untracked-files=no")}
            self.assertEqual(hashlib.sha256(observed["status"]).hexdigest(), TEXT_STATUS_SHA256)
            report = diagnostic.report(root, {"source": source}, observed, fixture.git,
                {"runId": "123456", "runAttempt": 1, "profile": "models-2"}, time.time() + 30)
            self.assertEqual(report["issueCodes"], [])
            self.assertEqual([p["path"] for p in report["paths"]], [WORKBOARD])
            self.assertEqual(report["unknownPathCount"], 0)
            self.assertTrue(report["checks"]["head"]["matches"])
            self.assertTrue(report["checks"]["tree"]["matches"])
            self.assertFalse(report["checks"]["trackedStatus"]["clean"])
            self.assertFalse(report["acceptanceGranted"])
            self.assertFalse(report["rawContentReturned"])
            self.assertEqual(report["paths"][0]["after"]["sha256"],
                hashlib.sha256(b'{"synthetic":"after"}\n').hexdigest())
            self.assertLessEqual(len(diagnostic.encoded(report)), 32768)
            self.assertLessEqual(report["hashedBytes"], 64 * 1024 * 1024)
            # The font names are literal file data, never a shell/glob argument.
            self.assertFalse(any(any(font in arg for font in FONTS) for call in fixture.calls for arg in call))

    def test_dirty_known_font_remains_metadata_only_and_never_accepted(self):
        with tempfile.TemporaryDirectory(prefix="v109-font-dirty-") as temporary:
            root = Path(temporary).resolve(); fixture = NativeFixture(root); source = fixture.seed()
            (root / FONTS[0]).write_bytes(b"synthetic changed font\n")
            observed = {"head": fixture.git("rev-parse", "HEAD"), "tree": fixture.git("rev-parse", "HEAD^{tree}"),
                "status": fixture.git("status", "--porcelain=v1", "--untracked-files=no")}
            report = diagnostic.report(root, {"source": source}, observed, fixture.git,
                {"runId": "123456", "runAttempt": 1, "profile": "models-2"}, time.time() + 30)
            self.assertEqual(report["issueCodes"], [])
            self.assertEqual([p["path"] for p in report["paths"]], [FONTS[0]])
            self.assertFalse(report["acceptanceGranted"])
            self.assertNotIn("synthetic changed font", str(report))


if __name__ == "__main__":
    unittest.main()
