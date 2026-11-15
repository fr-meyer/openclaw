import fs from 'node:fs';
import path from 'node:path';
export function checkInventory(expected, entries) {
 if (entries.length!==expected.length) throw Error('missing/extra executed files');
 const files=new Set();
 for (const entry of entries) {
  if (!expected.includes(entry.file) || files.has(entry.file) || entry.state!=='passed' || !Array.isArray(entry.testCases) || !entry.testCases.length) throw Error('bad executed inventory');
  if (entry.testCases.some(n=>typeof n!=='string' || !n) || new Set(entry.testCases).size!==entry.testCases.length) throw Error('bad assertion identity');
  files.add(entry.file);
 }
 return entries;
}
if (import.meta.main) {
 const expected=JSON.parse(process.env.B_EXPECTED_TESTS), dir=process.env.B_INVENTORY_DIR;
 const entries=fs.readdirSync(dir).map(n=>JSON.parse(fs.readFileSync(path.join(dir,n))));
 console.log(JSON.stringify({inventory:checkInventory(expected,entries)},null,2));
}
