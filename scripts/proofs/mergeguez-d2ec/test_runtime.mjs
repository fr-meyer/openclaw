// Exact runtime source under mocked filesystem/process owners; no real worker,
// child command, package, network, container, mount or OpenClaw import.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';
import { EventEmitter } from 'node:events';
import assert from 'node:assert/strict';
const root = path.dirname(new URL(import.meta.url).pathname);
const contract = JSON.parse(fs.readFileSync(root + '/contract.json', 'utf8'));
const code = fs.readFileSync(root + '/runtime.mjs', 'utf8');
async function fixture(phase, options = {}) {
  const timers = new Set();
  const commands = []; const writes = {}; const proc = { argv: ['node', '/proof/runtime.mjs', phase], env: { QUALIFICATION_JOB: '1-1', QUALIFICATION_NONCE: 'a'.repeat(64), QUALIFICATION_UPTIME_DEADLINE: '1000' }, versions: { node: '24.16.0' }, getuid: () => 1000, getgid: () => 1000, exitCode: 0 };
  const fakeFs = {
    readFileSync(p) {
      if (p === '/proof/contract.json') return JSON.stringify(contract);
      if (p === '/proc/uptime') return '10 0';
      if (p.endsWith('memory.max')) return options.unlimited ? 'max' : String(contract.memory_bytes);
      if (p.endsWith('memory.swap.max')) return options.swap ? '1' : '0';
      if (p.endsWith('pids.max')) return '512';
      if (p.endsWith('cpu.max')) return '400000 100000';
      if (p === '/control/gate.json') return JSON.stringify({ job: '1-1', phase, nonce: options.wrongGate ? 'b'.repeat(64) : 'a'.repeat(64), admitted: true });
      if (p.includes('/packages/') && p.endsWith('/package.json')) {
        const name=p.split('/packages/')[1].split('/')[0]; const exports=JSON.parse(JSON.stringify(contract.package_exports[name]));
        if(options.changedPackage) exports['.'].default='../escape.mjs';
        return JSON.stringify({exports});
      }
      if (p.endsWith('/package.json')) {
        const exports = Object.fromEntries(contract.sdk_exports.map(([key, runtime, types]) => [key, types === null ? { default: runtime } : { types, default: runtime }]));
        if (options.changedExport) exports['./plugin-sdk/sqlite-runtime'].types = './dist/plugin-sdk/sqlite-runtime.d.ts';
        if (options.escapedExport) exports['./plugin-sdk/core'].default = '../escape.js';
        if (options.malformedExport) exports['./plugin-sdk/core'] = null;
        return JSON.stringify({ packageManager: contract.packageManager, version: '2026.9.8', exports });
      }
      if (p.endsWith('/pnpm-lock.yaml')) return 'LOCKBODY';
      if (p.includes('/dist/')) return p.endsWith('.d.ts') || p.endsWith('.d.mts') ? 'DTS' : 'JS';
      throw new Error('unexpected fixture read ' + p);
    },
    realpathSync: p => p,
    lstatSync(p) {
      const output = p.includes('/dist/') && /\.(js|mjs|ts|mts|json)$/.test(p);
      if(options.missingPackage && p.endsWith('/packages/ai/dist/index.mjs') || options.missingRoot && p.endsWith('/build-info.json')) throw new Error('ENOENT fixture');
      if (options.missingRuntime && p.endsWith('/sqlite-runtime.js') || options.missingDeclaration && p.endsWith('/core.d.ts')) throw new Error('ENOENT fixture');
      return { dev: options.crossDevice && output ? 2 : 1, uid: 1000, gid: 1000, nlink: options.hardlink && output ? 2 : 1, size: options.noSdk && output ? 0 : 3, isSymbolicLink: () => !!options.outputLink && (output || p.endsWith('/plugin-sdk')), isDirectory: () => !output, isFile: () => output };
    },
    statSync: () => ({ size: options.noSdk ? 0 : 3, isFile: () => true }),
    readdirSync: () => [], existsSync: () => true, mkdirSync() {},
    writeFileSync(p, value) { writes[p] = value; },
  };
  const fakeCrypto = { createHash(name) {
    let body;
    return { update(b) { body = b; return this; }, digest(fmt) { return body === 'LOCKBODY' ? (options.wrongLock ? 'f'.repeat(64) : contract.lock_sha256) : crypto.createHash(name).update(body).digest(fmt); } };
  } };
  const fakeChild = {
    execFileSync(bin, args, opts) {
      if (bin === 'git') {
        if (args[2] === 'rev-parse') return args[3] === 'HEAD' ? (options.wrongHead ? 'f'.repeat(40) : contract.source_commit) : contract.source_tree;
        if (args[2] === 'write-tree') return contract.source_tree;
        if (args[2] === 'status') return options.dirty || (options.afterBuildDirty && commands.some(x => x.argv.join(' ') === 'pnpm build')) || (options.afterFetchDirty && commands.length === 4) ? ' M package.json' : '';
        if (args[2] === 'config') {
          if (options.credential) return 'http.x.extraheader retained';
          const e = new Error('absent config'); e.status = options.configError ? 2 : 1; e.stdout = ''; e.stderr = ''; throw e;
        }
      }
      if (bin === 'corepack') return '12.5.1';
      if (bin.endsWith('/bun')) return '1.4.2';
      throw new Error('unexpected executable ' + bin);
    },
    spawn(bin, args, opts) {
      commands.push({ argv: [bin, ...args], env: opts.env, cwd: opts.cwd });
      const child = new EventEmitter(); child.kill = () => {};
      queueMicrotask(() => options.spawnError ? child.emit('error', new Error('ENOENT fixture')) : child.emit('exit', options.failType && bin === 'pnpm' ? 1 : 0, null));
      return child;
    },
  };
  const context = vm.createContext({ process: proc, console: { log() {} }, setTimeout(fn, ms) { const id = {}; timers.add(id); return id; }, clearTimeout(id) { timers.delete(id); }, Buffer });
  const module = new vm.SourceTextModule(code, { context });
  const deps = { 'node:fs': fakeFs, 'node:path': path, 'node:crypto': fakeCrypto, 'node:child_process': fakeChild };
  await module.link(async name => {
    const dep = deps[name]; assert.ok(dep, 'unexpected native import');
    return new vm.SyntheticModule(['default', ...Object.keys(dep)], function () { this.setExport('default', dep); for (const k of Object.keys(dep)) this.setExport(k, dep[k]); }, { context });
  });
  await module.evaluate();
  return { commands, receipt: JSON.parse(writes['/qualification/reports/' + phase + '-receipt.json']), exit: proc.exitCode, timers: timers.size };
}
let checks = 0;
// These literal argv contracts come from pnpm v12.5.1's pinned Clap
// declarations. Comparing commands with the contract alone missed the
// unsupported fetch flag in the hosted run.
assert.deepEqual(contract.fetch_argv, ['fetch', '--store-dir=/qualification/pnpm-store']); checks++;
assert.deepEqual(contract.install_argv, ['install', '--offline', '--frozen-lockfile', '--ignore-scripts', '--store-dir=/qualification/pnpm-store', '--os=linux', '--cpu=x64', '--libc=glibc']); checks++;
assert.deepEqual(contract.compile_argv, [['pnpm', 'tsgo:prod'], ['pnpm', 'tsgo:scripts'], ['pnpm', 'build']]); checks++;
for (const options of [{ unlimited: true }, { swap: true }, { wrongGate: true }, { wrongHead: true }, { wrongLock: true }, { credential: true }, { configError: true }, { dirty: true }]) {
  const r = await fixture('offline-compile', options); assert.equal(r.receipt.complete, false); assert.equal(r.commands.length, 0); checks++;
}
const warm = await fixture('warm-fetch'); assert.equal(warm.receipt.complete, true); assert.deepEqual(warm.commands.at(-1).argv, ['corepack', contract.packageManager, ...contract.fetch_argv]); assert.ok(warm.commands.every(x => x.env.COREPACK_ENABLE_NETWORK === '1')); checks++;
assert.deepEqual(warm.commands.slice(0, 3).map(x => x.argv), [['corepack', 'enable', '--install-directory', '/qualification/toolchain/bin'], ['corepack', 'prepare', contract.packageManager, '--activate'], ['corepack', contract.packageManager, '--version']]); checks++;
const offline = await fixture('offline-compile'); assert.equal(offline.receipt.complete, true); assert.deepEqual(offline.commands.map(x => x.argv), [['corepack', contract.packageManager, ...contract.install_argv], ...contract.compile_argv]); assert.ok(offline.commands.every(x => x.env.COREPACK_ENABLE_NETWORK === '0' && !('GITHUB_TOKEN' in x.env))); checks++;
const failed = await fixture('offline-compile', { failType: true }); assert.equal(failed.receipt.complete, false); assert.equal(failed.commands.length, 2); assert.equal(failed.receipt.commands.at(-1).code, 1); checks++;
const missing = await fixture('offline-compile', { noSdk: true }); assert.equal(missing.receipt.complete, false); assert.equal(missing.receipt.commands.length, 4); checks++;
const spawnFailure = await fixture('offline-compile', { spawnError: true }); assert.equal(spawnFailure.receipt.complete, false); assert.equal(spawnFailure.timers, 0); assert.equal(spawnFailure.receipt.commands.length, 1); assert.match(spawnFailure.receipt.commands[0].error, /ENOENT/); checks++;
const finalDirty = await fixture('offline-compile', { afterBuildDirty: true }); assert.equal(finalDirty.receipt.complete, false); assert.equal(finalDirty.commands.length, 4); assert.match(finalDirty.receipt.error, /source changed/); checks++;
const fetchDirty = await fixture('warm-fetch', { afterFetchDirty: true }); assert.equal(fetchDirty.receipt.complete, false); assert.equal(fetchDirty.commands.length, 4); checks++;
assert.equal(offline.timers, 0); assert.equal(warm.timers, 0); assert.equal(failed.timers, 0); checks++;
assert.equal(offline.receipt.sdk.export_count, 352); assert.equal(offline.receipt.sdk.runtime_count, 352); assert.equal(offline.receipt.sdk.declaration_count, 158); assert.match(offline.receipt.sdk.sqlite_runtime.declaration_policy, /no types export/); checks++;
for (const options of [{missingRuntime:true},{missingDeclaration:true},{changedExport:true},{escapedExport:true},{malformedExport:true},{outputLink:true},{crossDevice:true},{hardlink:true}]) {
  const r=await fixture('offline-compile',options); assert.equal(r.receipt.complete,false); assert.equal(r.commands.length,4); checks++;
}
assert.equal(offline.receipt.packages.packages,16); assert.equal(offline.receipt.packages.exports,160); assert.equal(offline.receipt.packages.artifacts,323); checks++;
for(const options of [{changedPackage:true},{missingPackage:true},{missingRoot:true}]) { const r=await fixture('offline-compile',options); assert.equal(r.receipt.complete,false); assert.equal(r.commands.length,4); checks++; }
console.log(JSON.stringify({ checks, passed: checks, native_commands_or_network: 0, scope: 'exact-runtime-source-under-mocked-owners' }));
