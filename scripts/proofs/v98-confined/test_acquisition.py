"""Exercise the actual acquisition Bash and installed gh against loopback HTTP.

Only endpoint routing and a synthetic token are supplied by the test launcher.
The real CLI owns HTTP errors, redirects, binary output and credential stripping.
No GitHub request, image execution, or provider credential occurs in this suite.
"""
import http.server
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = Path(os.environ.get("V98_ACQUISITION_WORKFLOW",
                               ROOT / ".github/workflows/v98-confined-runtime-3.yml"))
TOKEN = "synthetic-v98-transport-test-token"
RUN_PATH = "/repos/fr-meyer/openclaw/actions/runs/37192724704"
ZIP_PATH = "/repos/fr-meyer/openclaw/actions/artifacts/11299504641/zip"


def acquisition_bash():
    # Read the real inline step; this parser only selects its literal Bash body.
    match = re.search(r"(?ms)^      - name: Acquire one retained artifact through GitHub API\n"
                      r"(.*?)(?=^      - name:|\Z)", WORKFLOW.read_text())
    if not match:
        raise AssertionError("acquisition step missing")
    body = match.group(1).split("        run: |\n", 1)[1]
    return textwrap.dedent(body)


class CheckoutSelectionTests(unittest.TestCase):
    def test_checkout_selection_contains_all_manifest_inputs(self):
        selection = re.search(r"(?m)^          sparse-checkout: \|\n"
                              r"((?:            .+\n)+)", WORKFLOW.read_text())
        self.assertIsNotNone(selection, "tooling checkout selection missing")
        paths = [line.strip() for line in selection.group(1).splitlines()]
        manifest = json.loads((ROOT / "scripts/proofs/v98-confined/source-manifest.json").read_text())
        missing = [row["path"] for row in manifest["files"] if not any(
            row["path"] == path or row["path"].startswith(path + "/") for path in paths)]
        self.assertEqual(missing, [], "fresh checkout excludes reviewed manifest inputs")


class ArtifactTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gh = shutil.which("gh")
        if not cls.gh:
            raise AssertionError("installed GitHub CLI is required; do not download it")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("fixture.txt", "synthetic transport bytes\n")
        cls.archive = stream.getvalue()
        owner = cls

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                owner.requests.append({"path": self.path,
                                       "accept": self.headers.get("Accept"),
                                       "authorization": self.headers.get("Authorization")})
                if self.path in (RUN_PATH, RUN_PATH + "/artifacts"):
                    payload, status = b'{"synthetic":true}', 200
                elif self.path == ZIP_PATH:
                    if self.headers.get("Accept") not in (
                            "application/json", "application/vnd.github+json") or owner.api_error:
                        status = owner.api_error or 415
                        payload = json.dumps({"message": "Unsupported Accept header",
                                              "status": str(status)}).encode()
                    else:
                        self.send_response(302)
                        # Changing host from 127.0.0.1 to localhost exercises
                        # the real CLI's cross-host Authorization handling.
                        self.send_header("Location", "http://localhost:%d/signed/fixture.zip"
                                         "?signature=synthetic" % self.server.server_port)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                elif self.path == "/signed/fixture.zip?signature=synthetic":
                    status = owner.download_error or 200
                    payload = owner.archive if status == 200 else b'{"message":"synthetic download refusal"}'
                else:
                    status, payload = 404, b"unexpected request"
                self.send_response(status)
                self.send_header("Content-Type", "application/zip" if status == 200 and
                                 self.path.startswith("/signed/") else "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=1)
        if cls.thread.is_alive():
            raise AssertionError("owned loopback fixture did not join")

    def run_acquisition(self, *, api_error=0, download_error=0):
        cls = type(self)
        cls.requests, cls.api_error, cls.download_error = [], api_error, download_error
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            # Keep real gh behavior. Rewrite only its API endpoint to loopback
            # and explicitly provide a harmless test token for the API host.
            launcher = bin_dir / "gh"
            launcher.write_text("#!" + sys.executable + "\n" + textwrap.dedent(f"""
                import os, sys
                args = sys.argv[1:]
                assert args[0] == 'api'
                assert args[-1].startswith('repos/fr-meyer/openclaw/actions/')
                args[-1] = 'http://127.0.0.1:{cls.server.server_port}/' + args[-1]
                args += ['-H', 'Authorization: token {TOKEN}']
                os.execv({cls.gh!r}, [{cls.gh!r}, *args])
                """))
            launcher.chmod(0o700)
            env = {"PATH": str(bin_dir) + os.pathsep + os.defpath,
                   "RUNNER_TEMP": str(root), "GH_TOKEN": TOKEN,
                   "GH_ENTERPRISE_TOKEN": TOKEN, "GH_CONFIG_DIR": str(root / "config"),
                   "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}
            result = subprocess.run(["/bin/bash", "-c", acquisition_bash()], env=env,
                                    capture_output=True, timeout=10, check=False)
            output = root / "v98-confined-acquisition/artifact.zip"
            data = output.read_bytes() if output.exists() else None
            return result, data, list(cls.requests)

    def test_actual_step_follows_redirect_with_binary_bytes_and_no_cross_host_token(self):
        result, data, requests = self.run_acquisition()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(data, self.archive)
        self.assertEqual([r["path"] for r in requests],
                         [RUN_PATH, RUN_PATH + "/artifacts", ZIP_PATH,
                          "/signed/fixture.zip?signature=synthetic"])
        self.assertEqual([r["authorization"] for r in requests[:3]], ["token " + TOKEN] * 3)
        self.assertIsNone(requests[3]["authorization"])
        self.assertNotIn(TOKEN.encode(), result.stderr)

    def test_http_415_stops_acquisition_without_redirect_or_retry(self):
        result, data, requests = self.run_acquisition(api_error=415)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"HTTP 415", result.stderr)
        self.assertNotEqual(data, self.archive)
        self.assertEqual([r["path"] for r in requests],
                         [RUN_PATH, RUN_PATH + "/artifacts", ZIP_PATH])

    def test_download_refusal_is_not_success_and_does_not_retry_or_forward_token(self):
        result, data, requests = self.run_acquisition(download_error=403)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"HTTP 403", result.stderr)
        self.assertNotEqual(data, self.archive)
        self.assertEqual(len(requests), 4)
        self.assertIsNone(requests[-1]["authorization"])


if __name__ == "__main__":
    unittest.main()
