import fs from 'node:fs';
import path from 'node:path';
const root='/app';
const inventory=[];
for (const scope of ['', 'ui']) {
 const base=path.join(root,scope), pkg=JSON.parse(fs.readFileSync(path.join(base,'package.json')));
 for (const group of ['dependencies','devDependencies','optionalDependencies']) {
  for (const [name,spec] of Object.entries(pkg[group]||{})) {
   const file=path.join(base,'node_modules',name,'package.json');
   if (!fs.existsSync(file)) { if(group==='optionalDependencies') continue; throw Error('missing '+scope+'/'+name); }
   const real=fs.realpathSync(path.dirname(file));
   const version=JSON.parse(fs.readFileSync(file)).version;
   if (/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(spec) && version!==spec) throw Error('version drift '+name);
   inventory.push({scope,name,spec,version,real,workspace:spec.startsWith('workspace:')});
  }
 }
}
fs.writeFileSync('/app/b-dependency-inventory.json',JSON.stringify(inventory,null,2));
