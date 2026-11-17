import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
// Trusted constant acquisition recipe. Candidate source must never be mounted in this container.
import fs from "node:fs";
const pin =
  "pnpm@12.9.0+sha512.8f64efa0b792986ca98ae568791bcd7722807e274c4f0c1d9853c62116495c584119db98762a2a5343b1684d361b9ae26fdd16d551666d7635346d3fae830ddd";
if (process.versions.node !== "24.16.0") throw Error("pinned Node mismatch");
const env = {
  PATH: "/usr/local/bin:/usr/bin:/bin",
  HOME: "/tmp",
  CI: "true",
  COREPACK_HOME: "/opt/corepack",
  COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
  COREPACK_DEFAULT_TO_LATEST: "0",
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1",
  XDG_CACHE_HOME: "/opt/offline-cache",
};
function run(bin, args) {
  const r = spawnSync(bin, args, { cwd: "/app", env, stdio: "inherit", timeout: 900000 });
  if (r.error || r.signal || r.status !== 0) throw Error("trusted dependency acquisition failed");
}
run("/usr/local/bin/corepack", ["enable"]);
run("/usr/local/bin/corepack", ["prepare", pin, "--activate"]);
const fixed = [
  "--frozen-lockfile",
  "--ignore-scripts",
  "--ignore-pnpmfile",
  "--store-dir=/opt/offline-store",
  "--registry=https://registry.npmjs.org",
];
run("/usr/local/bin/corepack", ["pnpm", "install", ...fixed]);
run("/usr/local/bin/corepack", ["pnpm", "rebuild", "--ignore-pnpmfile", "esbuild", "rastermill"]);
run("/usr/local/bin/corepack", ["pnpm", "install", "--lockfile-only", ...fixed]);
const hashes = [];
function walk(p) {
  for (const n of fs.readdirSync(p)) {
    const f = p + "/" + n,
      s = fs.lstatSync(f);
    if (s.isSymbolicLink()) throw Error("cache symlink");
    if (s.isDirectory()) walk(f);
    else if (s.isFile())
      hashes.push(crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex") + "  " + f);
    else throw Error("cache special file");
  }
}
walk("/opt/offline-cache");
if (!hashes.length) throw Error("cache empty");
fs.writeFileSync("/opt/offline-cache.SHA256", hashes.sort().join("\n") + "\n", { flag: "wx" });
run("/usr/local/bin/node", [
  "/opt/layout/no-copy-layout.mjs",
  "snapshot",
  "/opt/layout/image-manifest.json",
]);
