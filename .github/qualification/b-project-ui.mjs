import fs from 'node:fs';
import path from 'node:path';
export function projectionTarget(root, entry) {
 const target=entry.workspace ? path.join(root,path.relative('/app',entry.real)) : entry.real;
 if (!(entry.workspace && target===root) && !target.startsWith(entry.workspace ? root+'/' : '/app/')) throw Error('dependency escaped');
 return target;
}
export function projectUi() {
const root=process.cwd();
const inventory=JSON.parse(fs.readFileSync('/app/b-dependency-inventory.json'));
fs.mkdirSync('ui/node_modules',{recursive:true});
for (const entry of inventory) {
 const dest=path.join(root,entry.scope,'node_modules',entry.name);
 if (entry.scope==='ui') {
  const target=projectionTarget(root,entry);
  fs.mkdirSync(path.dirname(dest),{recursive:true});
  fs.symlinkSync(target,dest);
 }
 if (!fs.existsSync(path.join(dest,'package.json'))) throw Error('projected package missing '+entry.name);
 const pkg=JSON.parse(fs.readFileSync(path.join(dest,'package.json')));
 if(pkg.version!==entry.version) throw Error('projected version drift '+entry.name);
}
// Executable wrappers are immutable image-owned; no live Gateway or host dependency paths.
fs.symlinkSync('/app/node_modules/.bin','node_modules/.bin');
fs.symlinkSync('/app/ui/node_modules/.bin','ui/node_modules/.bin');
}
if (import.meta.main) projectUi();
