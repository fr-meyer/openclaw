// Task-only package/dependency filesystem adapter. It grants no release or native admission.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

function need(ok, message) { if (!ok) throw new Error(message); }
function hash(file) { const h = crypto.createHash('sha256'), fd = fs.openSync(file, 'r'), buffer = Buffer.alloc(1024 * 1024); try { let n; while ((n = fs.readSync(fd, buffer, 0, buffer.length, null))) h.update(buffer.subarray(0, n)); } finally { fs.closeSync(fd); } return h.digest('hex'); }
function inside(root, candidate) { return candidate === root || candidate.startsWith(root + path.sep); }

export function validateTarEntries(entries, cap) {
  const names = new Map(); let total = 0;
  for (const entry of entries) {
    need(typeof entry.path === 'string' && entry.path.length <= 4096, 'malformed tar path');
    const name = entry.path.replace(/\/$/, '');
    need(name === 'package' || name.startsWith('package/'), 'tar path outside package');
    need(!name.includes('\\') && !name.includes('\0') && !name.split('/').some(part => !part || part === '.' || part === '..'), 'unsafe tar path');
    need(!names.has(name), 'duplicate tar path');
    need(['File', 'Directory', 'SymbolicLink'].includes(entry.type), 'tar special/hard link refused');
    if (entry.type === 'File') { total += entry.size; need(Number.isSafeInteger(entry.size) && entry.size >= 0 && total <= cap, 'package extraction cap exceeded'); }
    if (entry.type === 'SymbolicLink') {
      need(typeof entry.linkpath === 'string' && entry.linkpath && !path.posix.isAbsolute(entry.linkpath) && !entry.linkpath.includes('\\') && !entry.linkpath.includes('\0'), 'absolute/unsafe tar link');
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(name), entry.linkpath));
      need(resolved === 'package' || resolved.startsWith('package/'), 'escaping tar link');
    }
    names.set(name, entry);
  }
  for (const [name, entry] of names) {
    for (let parent = path.posix.dirname(name); parent !== '.'; parent = path.posix.dirname(parent))
      need(!names.has(parent) || names.get(parent).type === 'Directory', 'tar ancestor overwrite/link trick');
    if (entry.type === 'SymbolicLink') {
      let target = path.posix.normalize(path.posix.join(path.posix.dirname(name), entry.linkpath));
      const seen = new Set([name]);
      while (names.get(target)?.type === 'SymbolicLink') {
        need(!seen.has(target), 'tar link cycle'); seen.add(target);
        target = path.posix.normalize(path.posix.join(path.posix.dirname(target), names.get(target).linkpath));
      }
      need(names.has(target), 'dangling tar link');
    }
  }
  return { total, files: entries.filter(entry => entry.type === 'File').length };
}

export function inventory(root, cap, deadline = Infinity, allowOwnedDeployHardlinks = false) {
  root = path.resolve(root); need(fs.realpathSync(root) === root && !fs.lstatSync(root).isSymbolicLink(), 'aliased inventory root');
  const device = fs.lstatSync(root).dev, entries = []; let total = 0;
  function visit(directory) {
    for (const name of fs.readdirSync(directory).sort()) {
      need(Date.now() < deadline, 'materialization deadline exhausted');
      const file = path.join(directory, name), st = fs.lstatSync(file), relative = path.relative(root, file);
      need(st.dev === device, 'artifact device crossing');
      if (st.isDirectory()) visit(file);
      else if (st.isSymbolicLink()) {
        const target = fs.readlinkSync(file);
        need(!path.isAbsolute(target) && inside(root, path.resolve(path.dirname(file), target)) && inside(root, fs.realpathSync(file)), 'absolute/escaping/dangling artifact link');
        entries.push({ path: relative, type: 'link', target });
      } else {
        need(st.isFile() && (st.nlink === 1 || allowOwnedDeployHardlinks), 'artifact special/hard-linked file');
        total += st.size; need(total <= cap, 'artifact cap exceeded');
        entries.push({ path: relative, type: 'file', bytes: st.size, sha256: hash(file) });
      }
    }
  }
  visit(root);
  return { totalBytes: total, entries, sha256: crypto.createHash('sha256').update(JSON.stringify(entries)).digest('hex') };
}

export function mergeDependencies(deployed, runnable, cap, deadline = Infinity) {
  const dependencyRoot = path.join(deployed, 'node_modules');
  inventory(deployed, cap, deadline, true); // pnpm's localized graph must be entirely contained before copying.
  const packed = inventory(runnable, cap, deadline), preserved = [];
  fs.mkdirSync(path.join(runnable, 'node_modules'), { recursive: true });
  function copy(source, target) {
    need(Date.now() < deadline, 'dependency merge deadline exhausted');
    const st = fs.lstatSync(source);
    if (st.isDirectory()) {
      if (fs.existsSync(target) || fs.lstatSync(target, { throwIfNoEntry: false })) {
        need(fs.lstatSync(target).isDirectory() && !fs.lstatSync(target).isSymbolicLink(), 'dependency directory collision');
        if (fs.existsSync(path.join(target, 'package.json'))) { preserved.push(path.relative(runnable, target)); return; }
      } else fs.mkdirSync(target, { mode: 0o755 });
      for (const name of fs.readdirSync(source).sort()) copy(path.join(source, name), path.join(target, name));
    } else if (st.isSymbolicLink()) {
      const link = fs.readlinkSync(source);
      need(!path.isAbsolute(link) && inside(deployed, fs.realpathSync(source)), 'deployed dependency link escapes');
      if (fs.lstatSync(target, { throwIfNoEntry: false })) {
        // Packed bundled packages outrank deployed workspace aliases, including the original AI.
        need(fs.lstatSync(target).isDirectory() && fs.existsSync(path.join(target, 'package.json')), 'dependency link collision');
        preserved.push(path.relative(runnable, target)); return;
      }
      fs.symlinkSync(link, target);
    } else {
      need(st.isFile(), 'deployed special file');
      if (fs.lstatSync(target, { throwIfNoEntry: false })) {
        need(fs.lstatSync(target).isFile() && hash(source) === hash(target), 'different dependency file collision');
      } else fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
    }
  }
  for (const name of fs.readdirSync(dependencyRoot).sort()) copy(path.join(dependencyRoot, name), path.join(runnable, 'node_modules', name));
  const merged = inventory(runnable, cap, deadline);
  const lookup = new Map(merged.entries.map(entry => [entry.path, entry]));
  for (const entry of packed.entries) need(JSON.stringify(lookup.get(entry.path)) === JSON.stringify(entry), 'original packed file changed during dependency materialization');
  return { packed, merged, preservedPackedPackages: preserved };
}

// Complete only the original checked package's lifecycle while this private stage is writable.
// The launcher and the read-only native artifact retain their ordinary lifecycle gates.
export async function completeRunnablePackageLifecycle(runnable, cap, deadline) {
  need(Number.isFinite(deadline) && Date.now() < deadline, 'package lifecycle deadline exhausted');
  runnable = path.resolve(runnable);
  const directory = fs.lstatSync(runnable);
  need(directory.isDirectory() && !directory.isSymbolicLink() && fs.realpathSync(runnable) === runnable, 'aliased lifecycle package root');
  const markers = new Set(['.openclaw-lifecycle-pending', 'dist/openclaw-install-guard']);
  const lockPath = path.join(runnable, '.openclaw-lifecycle-lock');
  need(!fs.lstatSync(lockPath, { throwIfNoEntry: false }), 'package lifecycle already has an unresolved owner');
  const pending = [...markers].filter(name => {
    const st = fs.lstatSync(path.join(runnable, name), { throwIfNoEntry: false });
    if (!st) return false;
    need(st.isFile() && !st.isSymbolicLink(), 'package lifecycle marker is not a regular file');
    return true;
  });
  const before = inventory(runnable, cap, deadline);
  const previous = new Map(before.entries.map(entry => [entry.path, entry]));
  const ownerPath = 'dist/infra/package-lifecycle.js';
  need(previous.get(ownerPath)?.type === 'file', 'original compiled package lifecycle owner absent');
  const owner = await import(pathToFileURL(path.join(runnable, ownerPath)).href);
  need(typeof owner.completePendingPackageLifecycle === 'function', 'original package lifecycle owner interface absent');
  const scriptBudgetMs = Math.min(60000, deadline - Date.now());
  need(scriptBudgetMs > 0, 'package lifecycle deadline exhausted');
  const completed = await owner.completePendingPackageLifecycle({ packageRoot: runnable, timeoutMs: scriptBudgetMs });
  need(Date.now() < deadline, 'package lifecycle deadline exhausted');
  const currentDirectory = fs.lstatSync(runnable);
  need(currentDirectory.dev === directory.dev && currentDirectory.ino === directory.ino && !currentDirectory.isSymbolicLink(), 'package lifecycle root generation changed');
  need(completed === (pending.length > 0), 'package lifecycle owner did not attest the observed pending work');
  need(!fs.lstatSync(lockPath, { throwIfNoEntry: false }), 'package lifecycle writer ownership remains unresolved');
  need([...markers].every(name => !fs.lstatSync(path.join(runnable, name), { throwIfNoEntry: false })), 'package lifecycle marker remains pending');
  const after = inventory(runnable, cap, deadline);
  const current = new Map(after.entries.map(entry => [entry.path, entry]));
  need([...markers].every(name => !current.has(name)), 'package lifecycle marker remains pending');
  for (const [name, entry] of previous) {
    if (!markers.has(name)) need(JSON.stringify(current.get(name)) === JSON.stringify(entry), 'package lifecycle changed checked runnable bytes: ' + name);
  }
  need(after.entries.every(entry => previous.has(entry.path)), 'package lifecycle introduced unchecked runnable content');
  return { schema: 'mergeguez.original-package-lifecycle-completion/v1', ownerPath,
    ownerSha256: previous.get(ownerPath).sha256, pendingMarkers: pending, completed,
    removedMarkers: pending, writerLockAbsent: true, directory: { dev: directory.dev, ino: directory.ino },
    beforeInventorySha256: before.sha256, afterInventorySha256: after.sha256,
    unchangedCheckedFileBytesAndLinks: true, metadataParity: 'file modes and empty directories are outside the baseline inventory contract',
    scriptBudgetMs, admissionOrReleaseAcceptance: false,
    inventory: after };
}

export function validateBuildReceipt(build, contract, expectedJob) {
  need(build.complete === true && build.source_commit === contract.source_commit && build.source_tree === contract.source_tree &&
    JSON.stringify(build.targeted_test_argv) === JSON.stringify(contract.targeted_test_argv) && JSON.stringify(build.compile_argv) === JSON.stringify(contract.compile_argv) && JSON.stringify(build.environment) === JSON.stringify(contract.compile_environment), 'fresh successful same-profile build receipt absent');
  need(typeof expectedJob === 'string' && /^[0-9]+-1$/.test(expectedJob) && build.job === expectedJob, 'build current job identity differs');
  const expected = [['corepack', contract.packageManager, ...contract.install_argv], ...contract.targeted_test_argv, ...contract.compile_argv];
  need(Array.isArray(build.commands) && JSON.stringify(build.commands.map(command => command.argv)) === JSON.stringify(expected) && build.commands.every(command => command.code === 0 && command.signal === null), 'actual successful install/type/build command receipts absent');
}

export async function materialize(source, tarball, deployed, runnable, buildFile, contractFile) {
  const contract = JSON.parse(fs.readFileSync(contractFile)), build = JSON.parse(fs.readFileSync(buildFile));
  validateBuildReceipt(build, contract, process.env.QUALIFICATION_JOB);
  const deadline = Date.now() + 120000;
  need(!fs.existsSync(runnable), 'runnable root already exists');
  const tar = createRequire(path.join(source, 'package.json'))('tar');
  const before = hash(tarball), entries = [];
  await tar.t({ file: tarball, strict: true, onReadEntry: entry => { need(Date.now() < deadline && entries.length < 200000, 'tar metadata/deadline cap exceeded'); entries.push({ path: entry.path, type: entry.type, size: entry.size, linkpath: entry.linkpath }); } });
  const listed = validateTarEntries(entries, contract.portable_runnable_unpacked_cap_bytes);
  const paths = new Set(entries.map(entry => entry.path));
  for (const relative of ['openclaw.mjs', 'dist/build-info.json', 'dist/plugin-sdk/sqlite-runtime.js', 'dist/proofs/native-ipc-gateway-driver.js', 'dist/proofs/native-ipc-gateway-api.js', 'dist/proofs/native-ipc-gateway-fixture.js'])
    need(paths.has('package/' + relative), 'actual checked package lacks required driver/runtime entry ' + relative);
  fs.mkdirSync(runnable, { mode: 0o700 });
  await tar.x({ file: tarball, cwd: runnable, strip: 1, preserveOwner: false, strict: true });
  need(hash(tarball) === before, 'checked package bytes changed during extraction');
  const result = mergeDependencies(deployed, runnable, contract.portable_runnable_unpacked_cap_bytes, deadline);
  const manifest = JSON.parse(fs.readFileSync(path.join(runnable, 'package.json')));
  const packedBundle = new Set(manifest.bundleDependencies ?? manifest.bundledDependencies ?? []);
  for (const [name, version] of Object.entries(manifest.dependencies ?? {})) {
    if (Object.hasOwn(manifest.optionalDependencies ?? {}, name)) continue;
    const resolved = fs.realpathSync(path.join(runnable, 'node_modules', name));
    need(inside(runnable, resolved), 'runtime dependency escapes artifact');
    const installed = JSON.parse(fs.readFileSync(path.join(resolved, 'package.json')));
    need(installed.name === name && typeof installed.version === 'string', 'runtime dependency identity absent');
    if (/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?$/.test(version)) need(installed.version === version, 'runtime dependency version differs from checked package');
    if (packedBundle.has(name)) need(result.packed.entries.some(entry => entry.path === 'node_modules/' + name + '/package.json'), 'packed bundled dependency was replaced');
  }
  const buildInfo = JSON.parse(fs.readFileSync(path.join(runnable, 'dist/build-info.json')));
  need(buildInfo.commit === contract.source_commit, 'package was built from another source');
  const packageLifecycle = await completeRunnablePackageLifecycle(runnable, contract.portable_runnable_unpacked_cap_bytes, deadline);
  const { inventory: lifecycleInventory, ...lifecycleReceipt } = packageLifecycle;
  const provenance = { packageLifecycle: lifecycleReceipt, schema: 'mergeguez.same-build-runnable-package/v1', source_commit: contract.source_commit, source_tree: contract.source_tree, job: build.job, checked_package_sha256: before, deploy_argv: contract.deploy_argv, build, packed: result.packed, deployed: inventory(deployed, contract.portable_runnable_unpacked_cap_bytes, deadline, true), runnable: lifecycleInventory, materializedBeforeLifecycle: result.merged, preservedPackedPackages: result.preservedPackedPackages, admissionOrReleaseAcceptance: false };
  const output = path.join(runnable, 'qualification-provenance.json');
  fs.writeFileSync(output, JSON.stringify(provenance) + '\n', { flag: 'wx', mode: 0o600 });
  need(listed.files === result.packed.entries.filter(entry => entry.type === 'file').length, 'extracted package inventory differs from original tarball');
  const finalInventory = inventory(runnable, contract.portable_runnable_unpacked_cap_bytes, deadline);
  const summary = { totalBytes: finalInventory.totalBytes, files: finalInventory.entries.length, inventory_sha256: finalInventory.sha256, provenance_sha256: hash(output), checked_package_sha256: before, packageLifecycle: lifecycleReceipt, admissionOrReleaseAcceptance: false };
  fs.writeFileSync(path.join(path.dirname(buildFile), 'runnable-materialization.json'), JSON.stringify(summary) + '\n', { flag: 'wx', mode: 0o600 });
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  if (process.argv.length !== 8) throw new Error('Expected source, tarball, deployed, runnable, build receipt and contract paths');
  materialize(...process.argv.slice(2)).then(result => process.stdout.write(JSON.stringify(result) + '\n')).catch(error => { process.stderr.write(String(error.stack ?? error) + '\n'); process.exitCode = 1; });
}
