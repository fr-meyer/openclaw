// Qualification tooling only. Never imports OpenClaw, starts a Gateway or calls a provider.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';

const contract = JSON.parse(fs.readFileSync('/proof/contract.json', 'utf8'));
const phase = process.argv[2];
const job = process.env.QUALIFICATION_JOB;
const nonce = process.env.QUALIFICATION_NONCE;
const deadline = Number(process.env.QUALIFICATION_UPTIME_DEADLINE);
const source = '/qualification/source';
const reports = '/qualification/reports';
const receipt = { schema: 'mergeguez.container-qualification/v1', phase, job, complete: false, commands: [] };
const uptime = () => Number(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]);
function requireThat(ok, message) { if (!ok) throw new Error(message); }
function remaining() { const n = deadline - uptime(); requireThat(Number.isFinite(n) && n > 0, 'shared work deadline exhausted'); return n; }
function sha(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function git(args) { return execFileSync('git', ['-C', source, ...args], { encoding: 'utf8', env: childEnv(false), timeout: Math.min(10000, remaining() * 1000) }).trim(); }
function childEnv(network) {
  return {
    PATH: '/qualification/toolchain/bin:/qualification/toolchain:/usr/local/bin:/usr/bin:/bin',
    HOME: '/qualification/home', TMPDIR: '/qualification/tmp', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    COREPACK_HOME: '/qualification/toolchain/corepack', COREPACK_ENABLE_NETWORK: network ? '1' : '0',
    PNPM_HOME: '/qualification/toolchain/bin', CI: 'true', GITHUB_ACTIONS: 'true',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null',
  };
}
function attestSource() {
  requireThat(process.getuid() === contract.compiler_uid && process.getgid() === contract.compiler_gid, 'compiler UID/GID mismatch');
  requireThat(fs.realpathSync(source) === source, 'source path alias');
  requireThat(git(['rev-parse', 'HEAD']) === contract.source_commit, 'wrong source HEAD');
  requireThat(git(['rev-parse', 'HEAD^{tree}']) === contract.source_tree, 'wrong source tree');
  requireThat(git(['write-tree']) === contract.source_tree, 'wrong source index');
  requireThat(git(['status', '--porcelain=v1']) === '', 'source changed before dispatch');
  requireThat(sha(source + '/pnpm-lock.yaml') === contract.lock_sha256, 'lock mismatch');
  const pkg = JSON.parse(fs.readFileSync(source + '/package.json', 'utf8'));
  requireThat(pkg.packageManager === contract.packageManager && pkg.version === '2026.9.8', 'source package/toolchain mismatch');
  // No trust override. Git must accept ownership under this actual UID.
  try {
    const extra = execFileSync('git', ['-C', source, 'config', '--local', '--get-regexp', '^(http\\..*extraheader|credential\\.|core\\.hooksPath)'], { encoding: 'utf8', env: childEnv(false), timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
    requireThat(!extra.trim(), 'unexpected checkout credential/hook config');
  } catch (e) { if (!(e.status === 1 && e.stdout === '' && e.stderr === '')) throw e; }
}
function inspectTree(root, allowToolLinks = false) {
  const device = fs.lstatSync('/qualification').dev;
  const stack = [root]; let count = 0;
  while (stack.length) {
    remaining(); const p = stack.pop(); const st = fs.lstatSync(p); count++;
    requireThat(st.dev === device, 'cross-device task input');
    requireThat(st.uid === contract.compiler_uid && st.gid === contract.compiler_gid, 'task input ownership changed');
    if (st.isSymbolicLink()) {
      const target = fs.realpathSync(p);
      requireThat(target.startsWith('/qualification/') || (allowToolLinks && target.startsWith('/usr/local/lib/node_modules/corepack/')), 'escaping input symlink');
    } else if (st.isDirectory()) { for (const n of fs.readdirSync(p)) stack.push(path.join(p, n)); }
    else requireThat(st.isFile(), 'special task input');
  }
  return count;
}
async function run(argv, network = false) {
  remaining(); const started = uptime();
  console.log(JSON.stringify({ event: 'command-start', argv, phase }));
  const child = spawn(argv[0], argv.slice(1), { cwd: source, env: childEnv(network), stdio: ['ignore', 'inherit', 'inherit'] });
  const timer = setTimeout(() => { child.kill('SIGTERM'); }, remaining() * 1000);
  let result;
  try {
    result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (code, signal) => resolve({ code, signal })); });
  } catch (error) {
    receipt.commands.push({ argv, error: String(error.message), elapsed_seconds: uptime() - started });
    throw error;
  } finally { clearTimeout(timer); }
  receipt.commands.push({ argv, ...result, elapsed_seconds: uptime() - started });
  requireThat(result.code === 0 && result.signal === null, 'command failed: ' + argv.join(' '));
  remaining();
}


function qualifyOutput(relative) {
  remaining();
  requireThat(typeof relative === 'string' && /^\.\/(?:dist\/|packages\/[a-z-]+\/dist\/)[a-zA-Z0-9._/-]+$/.test(relative) && relative.slice(2).split('/').every(x => x && x !== '.' && x !== '..'), 'unsafe compiled artifact path');
  const full = source + relative.slice(1);
  for (let directory = path.dirname(full); directory !== source; directory = path.dirname(directory)) {
    const st = fs.lstatSync(directory); requireThat(st.isDirectory() && !st.isSymbolicLink(), 'aliased compiled output directory');
  }
  const st = fs.lstatSync(full);
  requireThat(st.isFile() && !st.isSymbolicLink() && st.size > 0 && st.size <= contract.compiled_cap_bytes && st.nlink === 1 && st.dev === fs.lstatSync(source).dev && st.uid === contract.compiler_uid && st.gid === contract.compiler_gid, 'compiled artifact missing, empty or unsafe');
  return { path: relative, bytes: st.size, sha256: sha(full) };
}
function qualifyPackageOutputs() {
  const manifest = []; let exports = 0;
  for (const [name, expected] of Object.entries(contract.package_exports)) {
    const pkg = JSON.parse(fs.readFileSync(source + '/packages/' + name + '/package.json', 'utf8'));
    requireThat(JSON.stringify(Object.entries(pkg.exports).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0).map(([key,value]) => [key,Object.entries(value).sort()])) === JSON.stringify(Object.entries(expected).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0).map(([key,value]) => [key,Object.entries(value).sort()])), 'package export contract changed');
    const paths = new Set();
    for (const value of Object.values(expected)) {
      requireThat(value && typeof value === 'object' && !Array.isArray(value) && typeof value.types === 'string' && typeof value.default === 'string' && Object.keys(value).every(k => ['types','import','default'].includes(k)), 'unsupported package export conditions');
      for (const relative of Object.values(value)) {
        requireThat(typeof relative === 'string' && relative.startsWith('./dist/'), 'unsafe package output');
        paths.add('./packages/' + name + '/' + relative.slice(2));
      }
      exports++;
    }
    for (const relative of [...paths].sort()) manifest.push({ package: name, ...qualifyOutput(relative) });
  }
  for (const relative of contract.root_outputs) manifest.push({ package: 'openclaw', ...qualifyOutput(relative) });
  return { packages: Object.keys(contract.package_exports).length, exports, artifacts: manifest.length, output_manifest_sha256: crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex') };
}

function qualifySdkOutputs() {
  const pkg = JSON.parse(fs.readFileSync(source + '/package.json', 'utf8'));
  requireThat(pkg.exports && typeof pkg.exports === 'object' && !Array.isArray(pkg.exports), 'SDK exports absent');
  const actual = Object.entries(pkg.exports).filter(([key]) => key.startsWith('./plugin-sdk/')).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, value]) => {
    requireThat(/^\.\/plugin-sdk\/[a-z0-9-]+$/.test(key) && value && typeof value === 'object' && !Array.isArray(value), 'unsupported SDK export');
    requireThat(Object.keys(value).every(k => k === 'default' || k === 'types') && typeof value.default === 'string' && (!Object.hasOwn(value, 'types') || typeof value.types === 'string'), 'unsupported SDK export conditions');
    return [key, value.default, value.types ?? null];
  });
  requireThat(actual.length > 0 && JSON.stringify(actual) === JSON.stringify(contract.sdk_exports), 'SDK export contract changed');
  const manifest = [];
  for (const [key, runtime, declaration] of actual) {
    for (const [kind, relative] of [['runtime', runtime], ['declaration', declaration]]) {
      if (relative === null) continue; // Exact pinned JS-only export, never inferred from a missing file.
      const entry = key.slice('./plugin-sdk/'.length);
      requireThat(relative === './dist/plugin-sdk/' + entry + (kind === 'runtime' ? '.js' : '.d.ts'), 'unsafe SDK artifact path');
      manifest.push({ export: key, kind, ...qualifyOutput(relative) });
    }
  }
  const hashJson = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const sqlite = manifest.find(x => x.export === './plugin-sdk/sqlite-runtime' && x.kind === 'runtime');
  requireThat(sqlite && actual.find(x => x[0] === './plugin-sdk/sqlite-runtime')[2] === null, 'SQLite runtime-only contract missing');
  return { source_version: pkg.version, export_count: actual.length, runtime_count: manifest.filter(x => x.kind === 'runtime').length, declaration_count: manifest.filter(x => x.kind === 'declaration').length, export_contract_sha256: hashJson(actual), output_manifest_sha256: hashJson(manifest), sqlite_runtime: { runtime_sha256: sqlite.sha256, declaration_policy: 'private-local-only-runtime; no types export in ordinary build' } };
}

async function main() {
  requireThat(['warm-fetch', 'offline-compile'].includes(phase), 'unsupported phase');
  requireThat(/^[0-9]+-1$/.test(job) && /^[0-9a-f]{64}$/.test(nonce), 'missing host issuance identity');
  remaining();
  const limits = {};
  for (const k of ['memory.max', 'memory.swap.max', 'pids.max', 'cpu.max']) limits[k] = fs.readFileSync('/sys/fs/cgroup/' + k, 'utf8').trim();
  requireThat(limits['memory.max'] === String(contract.memory_bytes) && limits['memory.swap.max'] === '0' && limits['pids.max'] === String(contract.pids), 'actual container cgroup limit mismatch');
  const [quota, period] = limits['cpu.max'].split(' ').map(Number);
  requireThat(quota / period === contract.cpus, 'CPU containment mismatch');
  fs.mkdirSync(reports, { recursive: true });
  fs.writeFileSync(reports + '/' + phase + '-probe.json', JSON.stringify({ phase, job, uid: process.getuid(), gid: process.getgid(), limits }));
  // Host observes the real PID/cgroup/namespaces before any package operation.
  const waitUntil = Math.min(deadline, uptime() + 30);
  while (!fs.existsSync('/control/gate.json')) { requireThat(uptime() < waitUntil, 'host admission gate absent'); await new Promise(r => setTimeout(r, 100)); }
  const gate = JSON.parse(fs.readFileSync('/control/gate.json', 'utf8'));
  requireThat(gate.job === job && gate.phase === phase && gate.nonce === nonce && gate.admitted === true, 'wrong host admission gate');
  attestSource();
  requireThat(/^24\.(?:1[6-9]|[2-9][0-9])\./.test(process.versions.node), 'pinned Node does not satisfy original source engine');
  if (phase === 'warm-fetch') {
    await run(['corepack', 'enable', '--install-directory', '/qualification/toolchain/bin'], true);
    await run(['corepack', 'prepare', contract.packageManager, '--activate'], true);
    await run(['corepack', contract.packageManager, '--version'], true);
    const pnpm = execFileSync('corepack', [contract.packageManager, '--version'], { encoding: 'utf8', env: childEnv(false), cwd: source, timeout: 10000 }).trim();
    requireThat(pnpm === '12.5.1', 'pnpm version mismatch');
    const bun = execFileSync('/qualification/toolchain/bun', ['--version'], { encoding: 'utf8', env: childEnv(false), timeout: 10000 }).trim();
    requireThat(bun === '1.4.2', 'Bun version mismatch');
    receipt.versions = { node: process.versions.node, pnpm, bun };
    await run(['corepack', contract.packageManager, ...contract.fetch_argv], true);
  } else {
    await run(['corepack', contract.packageManager, ...contract.install_argv]);
    attestSource();
    receipt.private_input_entries = inspectTree(source);
    inspectTree('/qualification/toolchain', true);
    for (const argv of contract.compile_argv) {
      attestSource();
      // The original source wrappers perform their own physical compiler and
      // declaration ownership/heap admission. They are never substituted.
      await run(argv);
    }
    receipt.sdk = qualifySdkOutputs();
    receipt.packages = qualifyPackageOutputs();
  }
  attestSource();
  requireThat(sha(source + '/pnpm-lock.yaml') === contract.lock_sha256, 'lock changed during qualification');
  receipt.complete = true;
}
try { await main(); } catch (error) { receipt.error = String(error.message); process.exitCode = 1; }
finally { fs.mkdirSync(reports, { recursive: true }); fs.writeFileSync(reports + '/' + phase + '-receipt.json', JSON.stringify(receipt, null, 2) + '\n'); }
