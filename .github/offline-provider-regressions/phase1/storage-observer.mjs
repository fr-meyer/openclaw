// Trusted future read-only metadata observer. Never reads host file contents.
import fs from "node:fs";
const root = "/observed",
  seen = new Set();
let allocated = 0,
  files = 0;
function visit(p) {
  const s = fs.lstatSync(p, { bigint: true });
  const key = s.dev + ":" + s.ino;
  if (seen.has(key)) return;
  seen.add(key);
  allocated += Number(s.blocks) * 512;
  files++;
  if (files > 2000000) throw Error("observation inode ceiling");
  if (s.isDirectory()) for (const name of fs.readdirSync(p)) visit(p + "/" + name);
}
const s = fs.lstatSync(root, { bigint: true }),
  v = fs.statfsSync(root, { bigint: true });
visit(root);
process.stdout.write(
  JSON.stringify({
    schema: 1,
    complete: true,
    allocatedBytes: allocated,
    inodes: files,
    rootDevice: String(s.dev),
    filesystemType: String(v.type),
    rootInode: String(s.ino),
    filesystemUsedBytes: Number((v.blocks - v.bfree) * v.bsize),
    filesystemFreeBytes: Number(v.bavail * v.bsize),
  }) + "\n",
);
