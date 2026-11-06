// Canonical payload export, not authentication of an ambient installed tree.
// Linux CI/Docker only: held directory descriptors anchor every chosen open.
import {
  constants, openSync, closeSync, fstatSync, lstatSync, mkdirSync, readSync,
  writeSync, fsyncSync, fchmodSync,
} from 'node:fs';
import path from 'node:path';
import { validateNpmVendorProof, verifyInstalledNpmVendorDirectory, sha256 } from './npm-glob-vendor-proof.mjs';

const MAX_FILE = 8 * 1024 * 1024;
const MAX_BYTES = 32 * 1024 * 1024;
const MAX_DIRECTORIES = 512;
const MAX_DEPTH = 64;
const MAX_PATH_BYTES = 4096;
const COOPERATIVE_MS = 30000;
const ownErrors = new WeakSet();
function refuse(code) {
  const error = new Error(`npm-vendor.payload_${code}`);
  ownErrors.add(error); throw error;
}
function identity(s) {
  return [s.dev, s.ino, s.mode, s.size, s.mtimeNs, s.ctimeNs].map(String).join(':');
}
function statFd(fd) { return fstatSync(fd, { bigint: true }); }
function statAt(fd, name) { return lstatSync(`/proc/self/fd/${fd}/${name}`, { bigint: true }); }
function component(name) {
  if (typeof name !== 'string' || !name || name === '.' || name === '..' ||
      name.includes('/') || name.includes('\\') || /[\x00-\x1f\x7f]/.test(name) || name.normalize('NFC') !== name) refuse('path');
  return name;
}
function parts(name, absolute = false) {
  if (typeof name !== 'string' || Buffer.byteLength(name) > MAX_PATH_BYTES ||
      (absolute ? !path.isAbsolute(name) || path.resolve(name) !== name || name === '/' : path.isAbsolute(name))) refuse('path');
  const values = (absolute ? name.slice(1) : name).split('/').map(component);
  if (values.length > MAX_DEPTH) refuse('bounds');
  return values;
}
function ioFailure(error) {
  if (ownErrors.has(error)) throw error;
  const fixed = new Error('npm-vendor.payload_io');
  const code = error && (typeof error === 'object' || typeof error === 'function') ? Object.getOwnPropertyDescriptor(error, 'code') : undefined;
  if (code && 'value' in code && ['ENOENT', 'EEXIST', 'ELOOP', 'ENOTDIR', 'EACCES', 'EPERM', 'EMFILE', 'ENFILE', 'ENOSPC', 'EIO'].includes(code.value)) fixed.code = code.value;
  throw fixed; // no raw message, pathname, stack or arbitrary getter is copied.
}

export function stageNpmVendorPayload({ packageRoot, proof, patchBytes, outputRoot }) {
  // The existing owner alone establishes package/source/compiler/patch authority.
  const facts = validateNpmVendorProof(proof);
  if (!Buffer.isBuffer(patchBytes) || patchBytes.length !== proof.patch.size || sha256(patchBytes) !== proof.patch.sha256) refuse('patch');
  if (process.platform !== 'linux' || !Number.isInteger(constants.O_DIRECTORY) || !Number.isInteger(constants.O_NOFOLLOW)) refuse('platform');
  const sourceParts = parts(packageRoot, true), outputParts = parts(outputRoot, true);
  if (outputRoot === packageRoot || outputRoot.startsWith(`${packageRoot}/`) || packageRoot.startsWith(`${outputRoot}/`)) refuse('overlap');
  const prefixes = new Set(); let total = 0;
  for (const row of facts.files) {
    const names = parts(row.path); total += row.size;
    if (row.size > MAX_FILE || total > MAX_BYTES) refuse('bounds');
    for (let n = 1; n < names.length; n++) prefixes.add(names.slice(0, n).join('/'));
  }
  if (prefixes.size >= MAX_DIRECTORIES) refuse('bounds');
  const started = performance.now(), directories = new Map();
  const directoryFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
  const budget = () => { if (performance.now() - started >= COOPERATIVE_MS) refuse('elapsed'); };
  function childDirectory(fd, name, create = false) {
    budget(); component(name);
    if (create) { try { mkdirSync(`/proc/self/fd/${fd}/${name}`, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; } }
    const before = statAt(fd, name);
    if (before.isSymbolicLink()) refuse('source_link');
    if (!before.isDirectory()) refuse('directory_type');
    const child = openSync(`/proc/self/fd/${fd}/${name}`, directoryFlags);
    if (identity(before) !== identity(statFd(child))) { closeSync(child); refuse('source_changed'); }
    return child;
  }
  function absoluteDirectory(names) {
    let fd = openSync('/', directoryFlags);
    try {
      for (const name of names) {
        const child = childDirectory(fd, name); closeSync(fd); fd = child;
      }
      return fd;
    } catch (error) { closeSync(fd); throw error; }
  }
  function relativeDirectory(root, names, create = false, remember = false) {
    let fd = root, owned = false, prefix = '';
    try {
      for (const name of names) {
        const child = childDirectory(fd, name, create);
        if (owned) closeSync(fd);
        fd = child; owned = true; prefix = prefix ? `${prefix}/${name}` : name;
        if (remember) {
          const current = identity(statFd(fd)), prior = directories.get(prefix);
          if (prior !== undefined && prior !== current) refuse('source_changed');
          directories.set(prefix, current);
        }
      }
      return { fd, owned };
    } catch (error) { if (owned) closeSync(fd); throw error; }
  }
  let source, parent, output;
  try {
    source = absoluteDirectory(sourceParts);
    const sourceIdentity = identity(statFd(source));
    parent = absoluteDirectory(outputParts.slice(0, -1));
    const parentStat = statFd(parent);
    if (typeof process.getuid !== 'function' || parentStat.uid !== BigInt(process.getuid()) || Number(parentStat.mode & 0o077n) !== 0) refuse('parent');
    const outputName = outputParts.at(-1);
    // mkdir is exclusive. Existing output is neither adopted nor removed.
    mkdirSync(`/proc/self/fd/${parent}/${outputName}`, { mode: 0o700 });
    output = childDirectory(parent, outputName);
    const outputIdentity = identity(statFd(output));
    for (const row of facts.files) {
      budget(); const names = parts(row.path), name = names.at(-1);
      const from = relativeDirectory(source, names.slice(0, -1), false, true);
      let input;
      try {
        const before = statAt(from.fd, name);
        if (before.isSymbolicLink()) refuse('source_link');
        if (!before.isFile() || Number(before.mode & 0o7777n) !== row.mode || before.size !== BigInt(row.size)) refuse('source_file');
        input = openSync(`/proc/self/fd/${from.fd}/${name}`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        if (identity(statFd(input)) !== identity(before)) refuse('source_changed');
        const bytes = Buffer.alloc(row.size); let offset = 0;
        while (offset < bytes.length) {
          budget(); const count = readSync(input, bytes, offset, Math.min(65536, bytes.length - offset), null);
          if (!count) refuse('source_changed'); offset += count;
        }
        if (identity(statFd(input)) !== identity(before) || identity(statAt(from.fd, name)) !== identity(before)) refuse('source_changed');
        if (sha256(bytes) !== row.sha256) refuse('source_hash');
        // Only authenticated bytes reach the new output; unknown entries are
        // never enumerated, opened, copied, executed or declared authenticated.
        const to = relativeDirectory(output, names.slice(0, -1), true);
        let destination;
        try {
          destination = openSync(`/proc/self/fd/${to.fd}/${name}`, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
          let written = 0;
          while (written < bytes.length) {
            budget(); const count = writeSync(destination, bytes, written, Math.min(65536, bytes.length - written));
            if (!count) refuse('output_write'); written += count;
          }
          fchmodSync(destination, row.mode); fsyncSync(destination);
        } finally { if (destination !== undefined) closeSync(destination); if (to.owned) closeSync(to.fd); }
      } finally { if (input !== undefined) closeSync(input); if (from.owned) closeSync(from.fd); }
    }
    for (const [name, expected] of directories) {
      const selected = relativeDirectory(source, parts(name));
      try { if (identity(statFd(selected.fd)) !== expected) refuse('source_changed'); }
      finally { if (selected.owned) closeSync(selected.fd); }
    }
    const sourceAgain = absoluteDirectory(sourceParts);
    try { if (identity(statFd(source)) !== sourceIdentity || identity(statFd(sourceAgain)) !== sourceIdentity) refuse('source_changed'); }
    finally { closeSync(sourceAgain); }
    // The caller's private owned parent protects construction; package
    // directories must be traversable after public-pack/global delivery.
    for (const name of prefixes) {
      const selected = relativeDirectory(output, parts(name));
      try { fchmodSync(selected.fd, 0o755); fsyncSync(selected.fd); }
      finally { if (selected.owned) closeSync(selected.fd); }
    }
    fchmodSync(output, 0o755);
    // Directory timestamps change as authenticated files are created. Bind the
    // output's device/inode/type, then the unchanged owner checks its whole tree.
    const outputNow = statFd(output);
    if (outputNow.dev.toString() !== outputIdentity.split(':')[0] || outputNow.ino.toString() !== outputIdentity.split(':')[1] || Number(outputNow.mode & 0o7777n) !== 0o755 || !outputNow.isDirectory() ||
        identity(statAt(parent, outputName)) !== identity(outputNow)) refuse('output_changed');
    const beforeVerification = absoluteDirectory(outputParts);
    try { if (identity(statFd(beforeVerification)) !== identity(outputNow)) refuse('output_changed'); }
    finally { closeSync(beforeVerification); }
    budget(); const verified = verifyInstalledNpmVendorDirectory({ packageRoot: outputRoot, proof, patchBytes }); budget();
    const afterVerification = absoluteDirectory(outputParts);
    try { if (verified.packageRoot !== outputRoot || identity(statFd(output)) !== identity(outputNow) || identity(statFd(afterVerification)) !== identity(outputNow)) refuse('output_changed'); }
    finally { closeSync(afterVerification); }
    fsyncSync(output); fsyncSync(parent);
    return { sourceRoot: packageRoot, payloadRoot: outputRoot, npmVersion: verified.npmVersion,
      proofSha256: verified.proofSha256, inventorySha256: verified.inventorySha256, files: verified.files,
      payloadVerified: true, ambientSourceVerified: false };
  } catch (error) { return ioFailure(error); }
  finally { for (const fd of [output, parent, source]) if (fd !== undefined) closeSync(fd); }
}
