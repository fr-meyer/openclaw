// Small task-owned filesystem fixtures only. No native owner, package manager, tar parser, build or network execution.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { validateTarEntries, inventory, mergeDependencies, validateBuildReceipt } from './materialize.mjs';
const contract = JSON.parse(fs.readFileSync(new URL('./contract.json', import.meta.url)));
let checks = 0;
function check(fn) { fn(); checks++; }
const file = (name, bytes = 1) => ({ path: name, type: 'File', size: bytes });
const dir = name => ({ path: name, type: 'Directory', size: 0 });
const link = (name, target) => ({ path: name, type: 'SymbolicLink', linkpath: target, size: 0 });
check(() => assert.deepEqual(validateTarEntries([dir('package'), file('package/a'), link('package/b', 'a')], 5), { total: 1, files: 1 }));
for (const entries of [[file('/package/a')], [file('package/../a')], [file('package/a\\b')], [file('package//a')], [file('package/a'), file('package/a')], [{ ...file('package/a'), type: 'Link' }], [{ ...file('package/a'), size: -1 }], [{ ...file('package/a'), size: NaN }], [{ ...file('package/a'), path: null }], [link('package/a', '/tmp/a')], [link('package/a', '../../a')], [link('package/a', 'missing')], [link('package/a', 'b'), link('package/b', 'a')], [link('package/a', 'b'), file('package/a/sub'), file('package/b')]]) check(() => assert.throws(() => validateTarEntries(entries, 8)));
check(() => assert.throws(() => validateTarEntries([file('package/a', 9)], 8), /cap/));
const build = { complete: true, source_commit: contract.source_commit, source_tree: contract.source_tree, targeted_test_argv: contract.targeted_test_argv, compile_argv: contract.compile_argv, environment: contract.compile_environment, job: '1-1', commands: [['corepack', contract.packageManager, ...contract.install_argv], ...contract.targeted_test_argv, ...contract.compile_argv].map(argv => ({argv, code:0, signal:null})) };
check(() => validateBuildReceipt(build, contract, '1-1'));
for (const broken of [{ complete: false }, { source_commit: 'f'.repeat(40) }, { source_tree: 'f'.repeat(40) }, { targeted_test_argv: undefined }, { targeted_test_argv: [] }, { compile_argv: [['pnpm', 'build']] }, { environment: {} }, { job: '' }, { job: '2-1' }, { commands: [] }]) check(() => assert.throws(() => validateBuildReceipt({ ...build, ...broken }, contract, '1-1'), /build|job/));
check(() => assert.throws(() => validateBuildReceipt({ ...build, commands: build.commands.filter(command => command.argv[0] !== 'node') }, contract, '1-1'), /command receipts/));
check(() => assert.throws(() => validateBuildReceipt({ ...build, commands: build.commands.map(command => command.argv[0] === 'node' ? {...command, code:1} : command) }, contract, '1-1'), /command receipts/));
const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'mergeguez-materialize-')));
try {
  const deployed = path.join(root, 'deployed'), runnable = path.join(root, 'runnable');
  function put(base, name, bytes) { const file = path.join(base, name); fs.mkdirSync(path.dirname(file), {recursive:true}); fs.writeFileSync(file, bytes); }
  put(runnable, 'package.json', '{"name":"openclaw"}');
  put(runnable, 'node_modules/@openclaw/ai/package.json', '{"name":"@openclaw/ai","version":"packed"}');
  put(runnable, 'node_modules/@openclaw/ai/original.mjs', 'original checked bundled AI');
  put(deployed, 'node_modules/.pnpm/dependency/package.json', '{"name":"dependency","version":"1.0.0"}');
  put(deployed, 'node_modules/.pnpm/ai/package.json', '{"name":"@openclaw/ai","version":"deployed"}');
  fs.mkdirSync(path.join(deployed, 'node_modules/@openclaw'), {recursive:true});
  fs.symlinkSync('../.pnpm/ai', path.join(deployed, 'node_modules/@openclaw/ai'));
  fs.symlinkSync('.pnpm/dependency', path.join(deployed, 'node_modules/dependency'));
  const before = inventory(runnable, 4096);
  check(() => { const result = mergeDependencies(deployed, runnable, 8192); assert.ok(result.preservedPackedPackages.includes('node_modules/@openclaw/ai')); assert.equal(fs.readFileSync(path.join(runnable, 'node_modules/@openclaw/ai/original.mjs'), 'utf8'), 'original checked bundled AI'); assert.equal(fs.lstatSync(path.join(runnable, 'node_modules/@openclaw/ai')).isSymbolicLink(), false); for (const old of before.entries) assert.deepEqual(result.merged.entries.find(x => x.path === old.path), old); });
  check(() => assert.throws(() => inventory(runnable, 1), /cap/));
  put(deployed, 'node_modules/collision', 'deployed'); put(runnable, 'node_modules/collision', 'packed');
  check(() => assert.throws(() => mergeDependencies(deployed, runnable, 8192), /collision/));
  fs.unlinkSync(path.join(deployed, 'node_modules/collision')); fs.unlinkSync(path.join(runnable, 'node_modules/collision'));
  for (const target of ['/tmp', '../../escape', 'absent']) { const bad = path.join(runnable, 'bad'); fs.symlinkSync(target, bad); check(() => assert.throws(() => inventory(runnable, 8192))); fs.unlinkSync(bad); }
  const hard = path.join(runnable, 'hard'); fs.linkSync(path.join(runnable, 'package.json'), hard); check(() => assert.throws(() => inventory(runnable, 8192), /hard/)); fs.unlinkSync(hard);
  const alias = path.join(root, 'alias'); fs.symlinkSync(runnable, alias); check(() => assert.throws(() => inventory(alias, 8192), /aliased/));
  check(() => assert.throws(() => inventory(runnable, 8192, 0), /deadline/));
} finally { fs.rmSync(root, {recursive:true, force:true}); }
console.log(JSON.stringify({ checks, passed: checks, scope: 'small adapter fixtures only; actual tar/parser/deploy/native behavior unexecuted', native_commands_or_network: 0 }));
