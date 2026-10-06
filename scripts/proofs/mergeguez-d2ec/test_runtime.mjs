// Exact runtime source under mocked command owners, plus a tiny original-link
// filesystem control and one bounded Python retention fixture. No native worker,
// compiler/build, package manager, network, container, mount or OpenClaw import.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';
import { EventEmitter } from 'node:events';
import assert from 'node:assert/strict';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { validateBuildReceipt } from './materialize.mjs';
const root = path.dirname(new URL(import.meta.url).pathname);
const contract = JSON.parse(fs.readFileSync(root + '/contract.json', 'utf8'));
const code = fs.readFileSync(root + '/runtime.mjs', 'utf8');
async function fixture(phase, options = {}) {
  const timers = new Set();
  const commands = []; const writes = {}; const proc = { argv: ['node', '/proof/runtime.mjs', phase], env: { QUALIFICATION_JOB: '1-1', QUALIFICATION_NONCE: 'a'.repeat(64), QUALIFICATION_UPTIME_DEADLINE: '1000' }, versions: { node: '24.16.0' }, getuid: () => 1000, getgid: () => 1000, exitCode: 0 };
  const fakeFs = {
    readFileSync(p) {
      if (p === '/proof/contract.json') return JSON.stringify(contract);
      const sourceInput = contract.source_inputs.find(entry => p === '/qualification/source/' + entry.path);
      if (sourceInput) return 'SOURCEINPUT:' + sourceInput.path;
      if (Object.hasOwn(writes, p)) return writes[p];
      if (p === '/qualification/reports/runnable-materialization.json') return JSON.stringify({ totalBytes: 42, inventory_sha256: 'a'.repeat(64), admissionOrReleaseAcceptance: false });
      if (p === '/qualification/source/node_modules/npm/package.json') return JSON.stringify({version: options.wrongNpm ? '0.0.0' : contract.npm_version});
      if (p === '/artifact/qualification-provenance.json') {
        const build = {complete:true,job:options.oldBuildJob?'2-1':'1-1',source_commit:contract.source_commit,source_tree:contract.source_tree,targeted_test_argv:contract.targeted_test_argv,compile_argv:contract.compile_argv,environment:contract.compile_environment,commands:[['corepack',contract.packageManager,...contract.install_argv],...contract.targeted_test_argv, ...contract.compile_argv].map(argv=>({argv,code:0,signal:null}))};
        return JSON.stringify({build,job:build.job,source_commit:contract.source_commit,source_tree:contract.source_tree,admissionOrReleaseAcceptance:false,runnable:{sha256:crypto.createHash('sha256').update('[]').digest('hex')}});
      }
      if (p === '/qualification/native-output/native-observations.json') return JSON.stringify({completed:!options.nativeFailed,admissionOrReleaseAcceptance:false,priorArtifactParity:'unproved',ownership:options.lostUnknown?[]:[{status:'held-for-reconciliation'}]});
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
    realpathSync: p => { if (p.endsWith('/source-dependency-link')) throw new Error('source dependency link followed'); return p; },
    lstatSync(p) {
      const sourceInput = contract.source_inputs.find(entry => p === '/qualification/source/' + entry.path);
      const output = (p.includes('/dist/') && /\.(js|mjs|ts|mts|json)$/.test(p)) || p.endsWith('/fixture-emitted.js');
      if(options.missingPackage && p.endsWith('/packages/ai/dist/index.mjs') || options.missingRoot && p.endsWith('/build-info.json')) throw new Error('ENOENT fixture');
      if (options.missingRuntime && p.endsWith('/sqlite-runtime.js') || options.missingDeclaration && p.endsWith('/core.d.ts')) throw new Error('ENOENT fixture');
      return { dev: options.crossDevice && output ? 2 : 1, uid: 1000, gid: 1000, nlink: options.hardlink && output ? 2 : 1, size: sourceInput ? sourceInput.bytes : options.noSdk && output ? 0 : options.oversizedEmit && p.endsWith('/fixture-emitted.js') ? contract.compiled_cap_bytes + 1 : 3, isSymbolicLink: () => (options.sourceDependencyLink && p.endsWith('/source-dependency-link')) || !!options.outputLink && (output || p.endsWith('/plugin-sdk')), isDirectory: () => !output && !sourceInput, isFile: () => output || !!sourceInput };
    },
    statSync: () => ({ size: options.noSdk ? 0 : 3, isFile: () => true }),
    readdirSync: p => contract.compiled_roots.some(root => p === '/qualification/source/' + root) ? ['fixture-emitted.js', ...(options.sourceDependencyLink ? ['source-dependency-link'] : [])] : [], existsSync: () => true, mkdirSync() {},
    writeFileSync(p, value) { writes[p] = value; },
  };
  const fakeCrypto = { createHash(name) {
    let body;
    return { update(b) { body = b; return this; }, digest(fmt) { return typeof body === 'string' && body.startsWith('SOURCEINPUT:') ? (options.changedNamedSource ? 'f'.repeat(64) : contract.source_inputs.find(entry => entry.path === body.slice(12)).sha256) : body === 'LOCKBODY' ? (options.wrongLock ? 'f'.repeat(64) : contract.lock_sha256) : crypto.createHash(name).update(body).digest(fmt); } };
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
      if (bin === 'pnpm') return options.wrongNpm ? '0.0.0' : contract.npm_version;
      if (bin === 'corepack') return '12.5.1';
      if (bin.endsWith('/bun')) return '1.4.2';
      throw new Error('unexpected executable ' + bin);
    },
    spawn(bin, args, opts) {
      commands.push({ argv: [bin, ...args], env: opts.env, cwd: opts.cwd });
      const child = new EventEmitter(); child.kill = () => {};
      queueMicrotask(() => options.spawnError ? child.emit('error', new Error('ENOENT fixture')) : child.emit('exit', options.failTargeted && bin === 'node' && args[0] === 'scripts/run-vitest.mjs' || options.failType && bin === 'pnpm' ? 1 : 0, null));
      return child;
    },
  };
  const context = vm.createContext({ process: proc, console: { log() {} }, setTimeout(fn, ms) { const id = {}; timers.add(id); return id; }, clearTimeout(id) { timers.delete(id); }, Buffer });
  const module = new vm.SourceTextModule(code, { context });
  const deps = { 'node:fs': fakeFs, 'node:path': path, 'node:crypto': fakeCrypto, 'node:child_process': fakeChild, './materialize.mjs': {inventory() { return {entries:[],sha256:'a'.repeat(64)}; }, validateBuildReceipt} };
  await module.link(async name => {
    const dep = deps[name]; assert.ok(dep, 'unexpected native import');
    return new vm.SyntheticModule(['default', ...Object.keys(dep)], function () { this.setExport('default', dep); for (const k of Object.keys(dep)) this.setExport(k, dep[k]); }, { context });
  });
  await module.evaluate();
  return { commands, receipt: JSON.parse(writes[(phase === 'offline-native' ? '/qualification/native-output/' : '/qualification/reports/') + phase + '-receipt.json']), exit: proc.exitCode, timers: timers.size, buildReceiptWritten: Object.hasOwn(writes,'/qualification/reports/offline-compile-build.json'), buildReceipt: writes['/qualification/reports/offline-compile-build.json'] ? JSON.parse(writes['/qualification/reports/offline-compile-build.json']) : null };
}
let checks = 0;
// These literal argv contracts come from pnpm v12.5.1's pinned Clap
// declarations. Comparing commands with the contract alone missed the
// unsupported fetch flag in the hosted run.
assert.deepEqual(contract.fetch_argv, ['fetch', '--store-dir=/qualification/pnpm-store']); checks++;
assert.deepEqual(contract.install_argv, ['install', '--offline', '--frozen-lockfile', '--ignore-scripts', '--store-dir=/qualification/pnpm-store', '--os=linux', '--cpu=x64', '--libc=glibc']); checks++;
assert.deepEqual(contract.compile_argv, [['pnpm', 'tsgo:prod'], ['pnpm', 'tsgo:scripts'], ['pnpm', 'build']]); checks++;
assert.deepEqual(contract.targeted_test_argv, [["node", "scripts/run-vitest.mjs", "run", "src/cli/program/register.agent.test.ts", "src/commands/agent-via-gateway.test.ts", "src/gateway/server-plugin-subagent-runtime.test.ts", "src/gateway/server-managed-task-flow-runtime.test.ts", "src/tasks/managed-task-flow-host.test.ts", "packages/ai/src/transports/openai-responses-request-lifecycle.test.ts"]]); checks++;
for (const options of [{ unlimited: true }, { swap: true }, { wrongGate: true }, { wrongHead: true }, { wrongLock: true }, { credential: true }, { configError: true }, { dirty: true }]) {
  const r = await fixture('offline-compile', options); assert.equal(r.receipt.complete, false); assert.equal(r.commands.length, 0); checks++;
}
const warm = await fixture('warm-fetch'); assert.equal(warm.receipt.complete, true); assert.deepEqual(warm.commands.at(-1).argv, ['corepack', contract.packageManager, ...contract.fetch_argv]); assert.ok(warm.commands.every(x => x.env.COREPACK_ENABLE_NETWORK === '1')); checks++;
assert.deepEqual(warm.commands.slice(0, 3).map(x => x.argv), [['corepack', 'enable', '--install-directory', '/qualification/toolchain/bin'], ['corepack', 'prepare', contract.packageManager, '--activate'], ['corepack', contract.packageManager, '--version']]); checks++;
const offline = await fixture('offline-compile'); assert.equal(offline.receipt.complete, true); assert.deepEqual(offline.commands.map(x => x.argv), [['corepack', contract.packageManager, ...contract.install_argv], ...contract.targeted_test_argv, ...contract.compile_argv, contract.package_argv, contract.deploy_argv, contract.materialize_argv]); assert.ok(offline.commands.every(x => x.env.COREPACK_ENABLE_NETWORK === '0' && !('GITHUB_TOKEN' in x.env))); checks++;
assert.equal(offline.commands.filter(command => command.argv.join(' ') === 'pnpm build').length, 1); assert.deepEqual(offline.buildReceipt.targeted_test_argv, contract.targeted_test_argv); assert.equal(offline.buildReceipt.commands.length, 5); checks++;
const failedTargeted = await fixture('offline-compile', {failTargeted:true}); assert.equal(failedTargeted.receipt.complete,false); assert.equal(failedTargeted.commands.length,2); assert.equal(failedTargeted.commands.at(-1).argv[1],'scripts/run-vitest.mjs'); assert.equal(failedTargeted.buildReceiptWritten,false); checks++;
const changedNamedSource = await fixture('offline-compile', {changedNamedSource:true}); assert.equal(changedNamedSource.receipt.complete,false); assert.equal(changedNamedSource.commands.length,0); assert.match(changedNamedSource.receipt.error,/named source input changed/); checks++;
assert.equal(offline.receipt.source_identity.files,50); assert.match(offline.receipt.source_identity.kind,/source identity only/); checks++;
const failed = await fixture('offline-compile', { failType: true }); assert.equal(failed.receipt.complete, false); assert.equal(failed.commands.length, 3); assert.equal(failed.receipt.commands.at(-1).code, 1); checks++;
const missing = await fixture('offline-compile', { noSdk: true }); assert.equal(missing.receipt.complete, false); assert.equal(missing.receipt.commands.length, 5); checks++;
const spawnFailure = await fixture('offline-compile', { spawnError: true }); assert.equal(spawnFailure.receipt.complete, false); assert.equal(spawnFailure.timers, 0); assert.equal(spawnFailure.receipt.commands.length, 1); assert.match(spawnFailure.receipt.commands[0].error, /ENOENT/); checks++;
const finalDirty = await fixture('offline-compile', { afterBuildDirty: true }); assert.equal(finalDirty.receipt.complete, false); assert.equal(finalDirty.commands.length, 5); assert.match(finalDirty.receipt.error, /source changed/); checks++;
const fetchDirty = await fixture('warm-fetch', { afterFetchDirty: true }); assert.equal(fetchDirty.receipt.complete, false); assert.equal(fetchDirty.commands.length, 4); checks++;
assert.equal(offline.timers, 0); assert.equal(warm.timers, 0); assert.equal(failed.timers, 0); checks++;
assert.equal(offline.receipt.sdk.export_count, 352); assert.equal(offline.receipt.sdk.runtime_count, 352); assert.equal(offline.receipt.sdk.declaration_count, 158); assert.match(offline.receipt.sdk.sqlite_runtime.declaration_policy, /no types export/); checks++;
for (const options of [{missingRuntime:true},{missingDeclaration:true},{changedExport:true},{escapedExport:true},{malformedExport:true},{outputLink:true},{crossDevice:true},{hardlink:true}]) {
  const r=await fixture('offline-compile',options); assert.equal(r.receipt.complete,false); assert.equal(r.commands.length,5); checks++;
}
assert.equal(offline.receipt.packages.packages,16); assert.equal(offline.receipt.packages.exports,160); assert.equal(offline.receipt.packages.artifacts,326); checks++;
for(const options of [{changedPackage:true},{missingPackage:true},{missingRoot:true}]) { const r=await fixture('offline-compile',options); assert.equal(r.receipt.complete,false); assert.equal(r.commands.length,5); checks++; }
const native = await fixture('offline-native'); assert.equal(native.receipt.complete,true); assert.deepEqual(native.commands.map(x=>x.argv),[contract.native_argv]); assert.equal(native.commands[0].cwd,'/artifact'); assert.equal(native.receipt.native.admissionOrReleaseAcceptance,false); checks++;
for (const options of [{oldBuildJob:true},{nativeFailed:true},{lostUnknown:true}]) { const r=await fixture('offline-native',options); assert.equal(r.receipt.complete,false); assert.equal(r.commands.length,options.oldBuildJob?0:1); checks++; }
const wrongNpm=await fixture('offline-compile',{wrongNpm:true}); assert.equal(wrongNpm.receipt.complete,false); assert.equal(wrongNpm.commands.length,5); checks++;
assert.ok(offline.commands.slice(2,5).every(x=>x.env.OPENCLAW_BUILD_NATIVE_IPC_GATEWAY_QUALIFICATION==='1')); checks++;
const oversized = await fixture('offline-compile',{oversizedEmit:true}); assert.equal(oversized.receipt.complete,false); assert.equal(oversized.commands.length,5); assert.match(oversized.receipt.error,/compiled output cap/); assert.equal(oversized.buildReceiptWritten,false); checks++;
const sourceLinks = await fixture('offline-compile',{sourceDependencyLink:true}); assert.equal(sourceLinks.receipt.complete,true); assert.equal(sourceLinks.receipt.compiled_emits.source_links_not_followed,contract.compiled_roots.length); assert.equal(sourceLinks.buildReceiptWritten,true); checks++;

// Original8af finite module bytes, not a competing dependency-link implementation.
const originalHelperSource = "// Links a plugin's source-installed dependency packages under its packaged root.\nimport fs from \"node:fs\";\nimport path from \"node:path\";\n\n/**\n * Link every package installed under `<pluginDir>/node_modules` into `distNodeModules` so\n * dependency lookups rooted at the packaged plugin resolve the plugin-owned install.\n */\nexport function linkSourcePluginDependencies(pluginDir, distNodeModules) {\n  const sourceModules = path.join(pluginDir, \"node_modules\");\n  if (!fs.existsSync(sourceModules)) {\n    return;\n  }\n  const packages = fs.readdirSync(sourceModules).flatMap((name) => {\n    if (name.startsWith(\".\") && name !== \".bin\") {\n      return [];\n    }\n    return name.startsWith(\"@\")\n      ? fs.readdirSync(path.join(sourceModules, name)).map((child) => path.join(name, child))\n      : [name];\n  });\n  // An outer node_modules junction misresolves pnpm's relative links on Windows.\n  // Link canonical package roots individually; keep scopes real and payloads source-owned.\n  // Preserve .bin for managed launchers that resolve the plugin's private CLI shim.\n  for (const name of packages) {\n    const target = path.join(distNodeModules, name);\n    fs.mkdirSync(path.dirname(target), { recursive: true });\n    const canonical = fs.realpathSync(path.join(sourceModules, name));\n    // POSIX release checkouts relocate as a unit; Windows junctions require absolute targets.\n    fs.symlinkSync(\n      process.platform === \"win32\" ? canonical : path.relative(path.dirname(target), canonical),\n      target,\n      \"junction\",\n    );\n  }\n}\n";
assert.equal(crypto.createHash('sha256').update(originalHelperSource).digest('hex'),'523cd3654eb54ff272af89d4106f300c75ed6603c3c86edf4af1f27cd741a23c');
async function originalSourceRetentionControl() {
  const base=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'runnable-source-link-'))), source=path.join(base,'source');
  try {
    for(const name of contract.compiled_roots){fs.mkdirSync(path.join(source,name),{recursive:true});fs.writeFileSync(path.join(source,name,'index.js'),'owned compiled fixture');}
    const canonical=path.join(source,'node_modules/.pnpm/example@1/node_modules/example');fs.mkdirSync(canonical,{recursive:true});fs.writeFileSync(path.join(canonical,'index.js'),'source installed fixture');
    const plugin=path.join(source,'extensions/example');fs.mkdirSync(path.join(plugin,'node_modules'),{recursive:true});fs.symlinkSync(path.relative(path.join(plugin,'node_modules'),canonical),path.join(plugin,'node_modules/example'));
    const helperContext=vm.createContext({process:{platform:process.platform}}), helperModule=new vm.SourceTextModule(originalHelperSource,{context:helperContext});
    await helperModule.link(name=>{const dep=name==='node:fs'?fs:name==='node:path'?path:null;assert.ok(dep);return new vm.SyntheticModule(['default'],function(){this.setExport('default',dep);},{context:helperContext});});await helperModule.evaluate();
    helperModule.namespace.linkSourcePluginDependencies(plugin,path.join(source,'dist/extensions/example/node_modules'));
    const member=path.join(source,'dist/extensions/example/node_modules/example');assert.equal(fs.realpathSync(member),canonical);
    const ownedStat=fs.lstatSync(base), ports={...contract,compiler_uid:ownedStat.uid,compiler_gid:ownedStat.gid,compiled_cap_bytes:2048};
    const map=p=>p.startsWith('/qualification/source')?source+p.slice('/qualification/source'.length):p.startsWith('/qualification/reports')?base+'/reports'+p.slice('/qualification/reports'.length):p;
    const fixtureFs={readFileSync(p,...args){if(p==='/proof/contract.json')return JSON.stringify(ports);if(p==='/proc/uptime')return '0 0';return fs.readFileSync(map(p),...args);},lstatSync:p=>fs.lstatSync(map(p)),readdirSync:p=>fs.readdirSync(map(p)),mkdirSync:(p,o)=>fs.mkdirSync(map(p),o),writeFileSync:(p,...args)=>fs.writeFileSync(map(p),...args)};
    const processPort={argv:['node','/proof/runtime.mjs','source-body-fixture'],env:{QUALIFICATION_JOB:'1-1',QUALIFICATION_NONCE:'a'.repeat(64),QUALIFICATION_UPTIME_DEADLINE:'300'},exitCode:0};
    const noCommands={spawn(){throw Error('No compiler/native child permitted');},execFileSync(){throw Error('No compiler/native command permitted');}};
    const context=vm.createContext({process:processPort,Buffer,console:{log(){}},setTimeout,clearTimeout,Date}), module=new vm.SourceTextModule(code,{context});
    const deps={'node:fs':fixtureFs,'node:path':path,'node:crypto':crypto,'node:child_process':noCommands,'./materialize.mjs':{inventory(){throw Error('No native graph command permitted');},validateBuildReceipt}};
    await module.link(name=>{const dep=deps[name];assert.ok(dep);return new vm.SyntheticModule(['default',...Object.keys(dep)],function(){this.setExport('default',dep);for(const key of Object.keys(dep))this.setExport(key,dep[key]);},{context});});await module.evaluate();
    const measured=module.namespace.qualifyCompiledEmits();assert.equal(measured.source_links_not_followed,1);assert.equal(measured.regular_emitted_bytes,22*contract.compiled_roots.length);assert.ok(measured.regular_emitted_bytes<2048);
    fs.writeFileSync(path.join(source,'dist/index.js'),'x'.repeat(2049));assert.throws(()=>module.namespace.qualifyCompiledEmits(),/compiled output cap/);fs.writeFileSync(path.join(source,'dist/index.js'),'owned compiled fixture');
    // The child runs only actual filesystem-retention code with inert clock/mount
    // ports and synthetic receipts; it cannot count as native/compiler proof.
    const retained=JSON.parse(execFileSync('python3',['-c',"import importlib.util,json,os,sys\nfrom pathlib import Path\nfrom unittest.mock import patch\nproof=Path(sys.argv[1]);mount=Path(sys.argv[2]);control=mount/'control';control.mkdir()\nspec=importlib.util.spec_from_file_location('candidate_retention',proof/'driver.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)\nc=json.loads((proof/'contract.json').read_text())\ntry:list(d.compiled_walk(mount/'source',c['compiled_roots'],mount.stat().st_dev))\nexcept d.Refusal as error:assert str(error)=='escaping compiled link'\nelse:raise AssertionError('Expected original source graph link refusal')\ncommands=[['corepack',c['packageManager'],*c['install_argv']],*c['targeted_test_argv'],*c['compile_argv']]\nbuild={'complete':True,'job':'1-1','source_commit':c['source_commit'],'source_tree':c['source_tree'],'targeted_test_argv':c['targeted_test_argv'],'compile_argv':c['compile_argv'],'environment':c['compile_environment'],'commands':[{'argv':argv,'code':0,'signal':None} for argv in commands]}\n(mount/'reports/offline-compile-build.json').write_text(json.dumps(build))\nfor name in c['retention_roots']:(mount/name).mkdir()\nfiles={'package/checked.tgz':b'checked original tar fixture','runnable/index.mjs':b'owned runnable fixture','native-state/unknown.db':b'held unknown fixture','native-state/pre-migration.backup':b'original backup fixture','native-output/native-observations.json':b'unknown is not approval fixture'}\nfor name,data in files.items():(mount/name).write_bytes(data)\nargs=[str(mount),str(control),str(mount.stat().st_dev),str(os.getuid()),str(os.getgid()),'300','1-1','1']\nwith patch.object(Path,'is_mount',return_value=True),patch.object(d,'uptime',return_value=0):d.retain(args)\nwith d.tarfile.open(control/'runnable.tar.gz') as archive:\n for name,data in files.items():assert archive.extractfile(name).read()==data\nfor name,data in files.items():assert (mount/name).read_bytes()==data\nassert (mount/'source/dist/extensions/example/node_modules/example').is_symlink()\nprint(json.dumps({'complete':True,'actual_streamed_package_runnable_unknown_backup_preserved':True,'source_link_removed':False,'native_build_container_network_calls':0}))\n",root,base],{encoding:'utf8',timeout:5000,env:{PATH:process.env.PATH,PYTHONDONTWRITEBYTECODE:'1'}}));
    assert.equal(retained.complete,true);assert.equal(retained.actual_streamed_package_runnable_unknown_backup_preserved,true);assert.equal(retained.source_link_removed,false);
  } finally { fs.rmSync(base,{recursive:true,force:true}); }
}
await originalSourceRetentionControl();checks++;

console.log(JSON.stringify({ checks, passed: checks, native_commands_or_network: 0, scope: 'mocked compiler/native commands plus tiny original source-link and streamed retention control; one bounded Python fixture child' }));
