import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
SCRIPT = HERE / "verify-image-plugins.mjs"
VERSION = "2026.10.5"
CODEX = "0.160.0"

# Package/protocol fixtures; actual final-image Codex/broker proof remains required.
NATIVE_CODEX = r'''#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const mode = fs.readFileSync(path.join(__dirname, "mode"), "utf8");
if (process.env.OPENAI_API_KEY || process.env.NODE_OPTIONS || !process.env.CODEX_HOME) process.exit(9);
if (process.argv[2] === "--version") {
  console.log(`codex-cli ${mode === "wrong-cli" ? "0.159.0" : "0.160.0"}`);
  process.exit(0);
}
if (JSON.stringify(process.argv.slice(2)) !== JSON.stringify(["app-server", "--listen", "stdio://"])) process.exit(8);
let initialized = false;
const input = readline.createInterface({ input: process.stdin });
input.on("line", line => {
  const request = JSON.parse(line);
  if (request.method === "initialized") { initialized = true; return; }
  if (request.method !== "initialize" || request.params.clientInfo.version !== "2026.10.5") process.exit(7);
  if (mode === "flood") { process.stdout.write("x".repeat(65537)); return; }
  if (mode === "invalid-json") { console.log("not json"); return; }
  if (mode === "error") { console.log(JSON.stringify({id:1,error:{code:-1,message:"fixture"}})); return; }
  console.log(JSON.stringify({id:1,result:{userAgent:`openclaw/${mode === "wrong-initialize" ? "0.159.0" : "0.160.0"} (fixture)`}}));
});
input.on("close", () => process.exit(mode === "bad-exit" ? 23 : initialized ? 0 : 6));
'''

SQLITE_RUNTIME = r'''
import { Worker } from "node:worker_threads";
export async function openSqliteWorkerStore({ moduleUrl, databasePath }) {
  const worker = new Worker(moduleUrl, { workerData: { databasePath } });
  const pending = new Map(); let next = 0;
  worker.on("message", ({id, result}) => { pending.get(id)?.resolve(result); pending.delete(id); });
  worker.on("error", error => { for (const promise of pending.values()) promise.reject(error); pending.clear(); });
  return {
    execute(command) { return new Promise((resolve, reject) => {
      const id = ++next; pending.set(id, {resolve,reject}); worker.postMessage({id,command});
    }); },
    async close() { await worker.terminate(); }
  };
}
'''

SQLITE_WORKER = r'''
import { DatabaseSync } from "node:sqlite";
import { parentPort, workerData } from "node:worker_threads";
const db = new DatabaseSync(workerData.databasePath);
db.exec("CREATE TABLE proof (id TEXT PRIMARY KEY, value TEXT)");
let closed = false;
parentPort.on("message", ({id,command}) => {
  const {type,input} = command; let value;
  if (type === "connection.open") value = {connection:1,dataVersion:1};
  else if (type === "boards.register") db.prepare("INSERT INTO proof VALUES (?,?)").run(input.args[0],JSON.stringify(input.args[1]));
  else if (type === "boards.lookup") value = JSON.parse(db.prepare("SELECT value FROM proof WHERE id=?").get(input.args[0]).value);
  else if (type === "connection.close") { if (!closed) db.close(); closed = true; }
  else throw Error("unexpected command");
  parentPort.postMessage({id,result:{ok:true,value}});
});
'''


class ImagePluginPayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write_json("package.json", {"name": "openclaw", "version": VERSION, "type": "module"})
        self.codex_package = {
            "name": "@openclaw/codex", "version": VERSION,
            "dependencies": {"@openai/codex": CODEX},
            "openclaw": {"extensions": ["./index.ts"],
                         "compat": {"pluginApi": f">={VERSION}"},
                         "build": {"openclawVersion": VERSION},
                         "install": {"requiredPlatformPackages": ["@openai/codex-linux-x64"]}},
        }
        self.write_json("extensions/codex/package.json", self.codex_package)
        self.write_json("dist/extensions/codex/package.json", self.codex_package)
        self.write_json("extensions/codex/openclaw.plugin.json", {
            "id": "codex", "providers": ["codex"],
            "doctorContract": {"configRepair": True, "stateMigrations": [{"id": "codex-migration"}]},
        })
        self.write("dist/extensions/codex/index.js", "export default {};\n")
        self.cli_root = "dist/extensions/codex/node_modules/@openai/codex"
        self.write_json(f"{self.cli_root}/package.json", {
            "name": "@openai/codex", "version": CODEX, "type": "commonjs",
            "bin": {"codex": "bin/codex.js"},
            "optionalDependencies": {"@openai/codex-linux-x64": f"npm:@openai/codex@{CODEX}-linux-x64"},
        })
        self.platform_root = "dist/extensions/codex/node_modules/@openai/codex-linux-x64"
        self.write_json(f"{self.platform_root}/package.json", {
            "name": "@openai/codex", "version": f"{CODEX}-linux-x64",
            "os": ["linux"], "cpu": ["x64"], "type": "commonjs",
        })
        self.native_dir = f"{self.platform_root}/vendor/x86_64-unknown-linux-musl/bin"
        self.native = self.write(f"{self.native_dir}/codex", NATIVE_CODEX)
        self.native.chmod(0o755)
        self.write(f"{self.native_dir}/mode", "success")
        self.write(f"{self.cli_root}/bin/codex.js", r'''
const {spawnSync} = require("node:child_process");
const path = require("node:path");
const root = path.dirname(require.resolve("@openai/codex-linux-x64/package.json"));
const result = spawnSync(path.join(root,"vendor/x86_64-unknown-linux-musl/bin/codex"), process.argv.slice(2), {encoding:"utf8",env:process.env});
process.stdout.write(result.stdout || ""); process.stderr.write(result.stderr || ""); process.exit(result.status ?? 1);
''')
        workboard = {"name": "@openclaw/workboard", "version": VERSION,
                     "peerDependencies": {"openclaw": f">={VERSION}"},
                     "openclaw": {"extensions": ["./index.ts"],
                                  "build": {"workerEntries": ["./src/sqlite-store.worker.ts"]}}}
        self.write_json("extensions/workboard/package.json", workboard)
        self.write_json("dist/extensions/workboard/package.json", workboard)
        self.write_json("extensions/workboard/openclaw.plugin.json", {"id": "workboard"})
        self.write("dist/extensions/workboard/index.js", "export default {};\n")
        self.write("dist/extensions/workboard/src/sqlite-store.worker.js", SQLITE_WORKER)
        self.write("dist/plugin-sdk/sqlite-runtime.js", SQLITE_RUNTIME)

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def write_json(self, path, content):
        return self.write(path, json.dumps(content))

    def inspect(self, extensions="codex", version=CODEX):
        env = {**os.environ, "OPENAI_API_KEY": "synthetic-must-not-reach-child"}
        return subprocess.run(["node", str(SCRIPT), str(self.root), extensions, VERSION, version],
                              capture_output=True, text=True, timeout=40, env=env)

    def test_native_cli_handshake_and_workboard_round_trip(self):
        result = self.inspect("codex,workboard")
        self.assertEqual(result.returncode, 0, result.stderr)
        codex, workboard = json.loads(result.stdout)
        self.assertEqual(codex["version"], VERSION)
        self.assertEqual(codex["codexRuntime"], {
            "packageVersion": CODEX, "platformAlias": "@openai/codex-linux-x64",
            "platformVersion": f"{CODEX}-linux-x64", "cliVersion": CODEX,
            "initializeVersion": CODEX, "initialized": True, "shutdown": "exited",
        })
        self.assertEqual(workboard["workboardRuntime"], {"worker": "sqlite", "roundTrip": True, "closed": True})

    def test_missing_compiled_payload_and_stale_plugin_fail(self):
        entry = self.root / "dist/extensions/codex/index.js"
        entry.unlink()
        result = self.inspect()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("index.js", result.stderr)
        entry.write_text("export default {};\n")
        self.codex_package["version"] = "2026.9.6"
        self.write_json("extensions/codex/package.json", self.codex_package)
        result = self.inspect()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity changed", result.stderr)

    def test_missing_source_pin_and_platform_version_mismatch_fail(self):
        for pin in ("", "0.159.0"):
            with self.subTest(pin=pin):
                result = self.inspect(version=pin)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("source", result.stderr)
        path = self.root / self.platform_root / "package.json"
        metadata = json.loads(path.read_text())
        metadata["version"] = "0.159.0-linux-x64"
        path.write_text(json.dumps(metadata))
        result = self.inspect()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("platform package differs", result.stderr)

    def test_missing_or_escaped_native_executable_fails(self):
        self.native.unlink()
        result = self.inspect()
        self.assertNotEqual(result.returncode, 0)
        self.native.symlink_to("/bin/true")
        result = self.inspect()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escaped image root", result.stderr)

    def test_cli_and_handshake_refusals_never_produce_success(self):
        for mode, diagnostic in (("wrong-cli", "CLI version"), ("wrong-initialize", "runtime version"),
                                 ("error", "initialize returned an error"), ("invalid-json", "invalid JSON"),
                                 ("bad-exit", "shut down cleanly"), ("flood", "output exceeded")):
            with self.subTest(mode=mode):
                self.write(f"{self.native_dir}/mode", mode)
                result = self.inspect()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_initialize_deadline_kills_and_joins_unresponsive_child(self):
        self.native.write_text("#!/usr/bin/env node\nprocess.stdin.resume();\n")
        code = f'''import {{smokeCodexAppServer}} from {json.dumps(SCRIPT.as_uri())};
try {{ await smokeCodexAppServer({json.dumps(str(self.native))}, {{PATH:process.env.PATH,HOME:{json.dumps(str(self.root))}}}, "2026.10.5", "0.160.0", 100); process.exitCode=2; }}
catch(error) {{ if (!error.message.includes("timed out")) throw error; console.log("joined refusal"); }}'''
        result = subprocess.run(["node", "--input-type=module", "-e", code], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "joined refusal")

    def test_workboard_requires_worker_and_successful_native_operation(self):
        worker = self.root / "dist/extensions/workboard/src/sqlite-store.worker.js"
        worker.unlink()
        result = self.inspect("codex,workboard")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sqlite-store.worker.js", result.stderr)
        worker.write_text(SQLITE_WORKER.replace("{ok:true,value}", "{ok:false}"))
        result = self.inspect("codex,workboard")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Workboard native operation failed", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
