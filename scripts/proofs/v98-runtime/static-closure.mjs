// Parse image JavaScript as data with an already installed, digest-pinned parser.
// This program never imports, evaluates or reproduces an image module pathname.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
const [inventoryPath, objectsPath, parserPath, output] = process.argv.slice(2);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
if (hash(fs.readFileSync(parserPath)) !== "953573b8fdab71599749ea5f2b33d3e760c2116178f9423ee7458dbe39d59453") throw Error("PARSER_CHANGED");
const { parse } = await import(pathToFileURL(parserPath).href);
const inventoryBytes=fs.readFileSync(inventoryPath);
if(hash(inventoryBytes)!=="e7c50cfcb33072e780dbae849147d3fbc33b2bcb41b7067ae9f13a05d9116719") throw Error("INVENTORY_CHANGED");
const entries = new Map(JSON.parse(zlib.gunzipSync(inventoryBytes)).entries.map((r) => [r.path, r]));
function resolveFile(name) {
  let current = path.posix.normalize(name);
  for (let hop = 0; hop < 40; hop++) {
    const parts = current.split("/").filter(Boolean);
    let changed = false;
    for (let i = 0; i < parts.length; i++) {
      const p = "/" + parts.slice(0, i + 1).join("/");
      const r = entries.get(p);
      if (!r) throw Error("ABSENT:" + p);
      if (r.type === "symlink") {
        current = path.posix.resolve(path.posix.dirname(p), r.target, ...parts.slice(i + 1));
        changed = true; break;
      }
      if (i < parts.length - 1 && r.type !== "directory") throw Error("NON_DIRECTORY:" + p);
    }
    if (!changed) {
      if (entries.get(current)?.type !== "file") throw Error("NON_FILE:" + current);
      return current;
    }
  }
  throw Error("LINK_LOOP");
}
function bytes(p) {
  const r = entries.get(p), b = fs.readFileSync(path.join(objectsPath, r.sha256));
  if (hash(b) !== r.sha256 || b.length !== r.bytes) throw Error("CAPTURE_CHANGED:" + p);
  return b;
}
function condition(value, kind) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) throw Error("EXPORT_ARRAY_UNSUPPORTED");
  if (!value || typeof value !== "object") throw Error("EXPORT_TARGET_UNSUPPORTED");
  for (const [key, target] of Object.entries(value)) {
    if (["node", kind, "default", "node-addons"].includes(key)) return condition(target, kind);
  }
  throw Error("EXPORT_CONDITION_UNRESOLVED");
}
function packageTarget(base, subpath, kind) {
  const manifest = resolveFile(base + "/package.json");
  const pkg = JSON.parse(bytes(manifest));
  metadata.add(manifest);
  let target;
  if (pkg.exports !== undefined) {
    const exp = pkg.exports;
    if (typeof exp === "object" && exp !== null && !Array.isArray(exp) && Object.keys(exp).some((x) => x.startsWith("."))) {
      if (Object.hasOwn(exp, subpath)) target = condition(exp[subpath], kind);
      else {
        const keys = Object.keys(exp).filter((x) => x.includes("*"));
        const matches = keys.filter((x) => {
          const [pre, post] = x.split("*"); return subpath.startsWith(pre) && subpath.endsWith(post);
        }).sort((a,b) => b.indexOf("*") - a.indexOf("*") || b.length - a.length);
        if (!matches.length) throw Error("EXPORT_ABSENT:" + subpath);
        const key = matches[0], [pre, post] = key.split("*");
        const replace = subpath.slice(pre.length, subpath.length - post.length);
        if (replace.split("/").some((x) => ["..", "node_modules"].includes(x))) throw Error("EXPORT_ESCAPE");
        target = condition(exp[key], kind).replaceAll("*", replace);
      }
    } else if (subpath === ".") target = condition(exp, kind);
    else throw Error("PACKAGE_SUBPATH_ABSENT");
    if (!target.startsWith("./") || target.includes("/../")) throw Error("EXPORT_ESCAPE");
    return resolveFile(base + "/" + target);
  }
  const candidate = subpath === "." ? pkg.main || "index.js" : subpath.slice(2);
  for (const suffix of kind === "require" ? ["", ".js", ".json", ".node", "/index.js"] : [""]) {
    try { return resolveFile(base + "/" + candidate + suffix); } catch {}
  }
  throw Error("LEGACY_PACKAGE_ABSENT");
}
function resolveSpecifier(s, from, kind) {
  if (s.startsWith("node:")) { builtins.add(s); return null; }
  if (s.startsWith(".")) {
    const name = path.posix.resolve(path.posix.dirname(from), s);
    for (const suffix of kind === "require" ? ["", ".js", ".json", ".node", "/index.js"] : [""]) {
      try { return resolveFile(name + suffix); } catch {}
    }
    throw Error("RELATIVE_ABSENT:" + name);
  }
  if (s.startsWith("/")) return resolveFile(s);
  if (s.startsWith("#")) {
    let dir=path.posix.dirname(from);
    while (dir !== "/") {
      if (entries.has(dir+"/package.json")) {
        const p=resolveFile(dir+"/package.json"), pkg=JSON.parse(bytes(p)); metadata.add(p);
        const target=condition(pkg.imports?.[s],kind);
        if (!target.startsWith("./")) throw Error("IMPORTS_TARGET_UNSUPPORTED");
        return resolveFile(path.posix.resolve(dir,target));
      }
      dir=path.posix.dirname(dir);
    }
    throw Error("IMPORTS_ABSENT");
  }
  if (s.includes(":")) throw Error("UNSUPPORTED_SPECIFIER:" + s);
  // Node's old builtin spellings may occur in external CommonJS modules.
  if (["assert","buffer","child_process","crypto","events","fs","fs/promises","http","https","module","os","path","perf_hooks","process","stream","stream/promises","string_decoder","timers","url","util","v8","worker_threads","zlib"].includes(s)) { builtins.add("node:"+s); return null; }
  const parts = s.split("/"), n = s.startsWith("@") ? 2 : 1;
  const pkg = parts.slice(0,n).join("/"), sub = parts.length === n ? "." : "./" + parts.slice(n).join("/");
  let dir = path.posix.dirname(from);
  while (true) {
    const base = dir + "/node_modules/" + pkg;
    if (entries.has(base)) {
      let exists=true;
      try { resolveFile(base+"/package.json"); } catch(e) { if (String(e.message).startsWith("ABSENT:")) exists=false; else throw e; }
      if (exists) return packageTarget(base, sub, kind);
    }
    if (dir === "/") break;
    dir = path.posix.dirname(dir);
  }
  throw Error("PACKAGE_ABSENT:" + s);
}
const root = "/app/dist/openclaw-state-db-CgJKJRub.mjs";
const queue = [root,"/app/dist/infra/sqlite-readonly-location.worker.js","/app/dist/infra/sqlite-source-revision.worker.js","/app/dist/infra/fs-safe-copy.worker.js","/app/dist/state/openclaw-state-read.worker.js"], seen = new Set(), edges = [], unresolved = [], metadata = new Set(), builtins = new Set(), facts = [];
function enqueue(from, specifier, kind, site) {
  try {
    const target = resolveSpecifier(specifier, from, kind);
    edges.push({from,specifier,kind,target,site});
    if (target && !seen.has(target)) queue.push(target);
  } catch (e) { unresolved.push({from,specifier,kind,site,error:String(e.message)}); }
}
while (queue.length) {
  const file = queue.shift(); if (seen.has(file)) continue; seen.add(file);
  if (!file.endsWith(".mjs") && !file.endsWith(".js") && !file.endsWith(".cjs")) continue;
  let source, ast;
  try {
    source = bytes(file).toString("utf8");
    try { ast = parse(source, {ecmaVersion:"latest",sourceType:"module",locations:true}); }
    catch { ast = parse(source, {ecmaVersion:"latest",sourceType:"script",locations:true,allowReturnOutsideFunction:true}); }
  } catch(e) { unresolved.push({from:file,error:String(e.message)}); continue; }
  const todo=[ast];
  const requireNames=new Set(["require","__require"]);
  const declarations=[ast];
  while(declarations.length) {
    const n=declarations.pop(); if (!n || typeof n !== "object") continue;
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init?.type === "CallExpression" && (n.init.callee.name === "createRequire" || n.init.callee.property?.name === "createRequire")) requireNames.add(n.id.name);
    for(const v of Object.values(n)) { if(Array.isArray(v)) declarations.push(...v); else if(v && typeof v === "object") declarations.push(v); }
  }
  while(todo.length) {
    const n=todo.pop(); if (!n || typeof n !== "object") continue;
    const site=n.loc?.start.line;
    if (["ImportDeclaration","ExportAllDeclaration","ExportNamedDeclaration"].includes(n.type) && n.source) enqueue(file,n.source.value,"import",site);
    if (n.type === "ImportExpression") {
      if (n.source.type === "Literal" && typeof n.source.value === "string") enqueue(file,n.source.value,"import",site);
      else unresolved.push({from:file,kind:"computed-import",site,expression:source.slice(n.start,n.end)});
    }
    if (n.type === "CallExpression" && (n.callee.type === "Identifier" && requireNames.has(n.callee.name) || n.callee.type === "CallExpression" && (n.callee.callee.name === "createRequire" || n.callee.callee.property?.name === "createRequire"))) {
      if (n.arguments[0]?.type === "Literal" && typeof n.arguments[0].value === "string") enqueue(file,n.arguments[0].value,"require",site);
      else unresolved.push({from:file,kind:"computed-require",site,expression:source.slice(n.start,n.end)});
    }
    if (n.type === "NewExpression" && (n.callee.name === "Worker" || n.callee.property?.name === "Worker")) facts.push({from:file,kind:"Worker",site,expression:source.slice(n.start,n.end)});
    if (n.type === "CallExpression" && ["resolveRuntimeWorkerUrl","getBinding","getNativeBinding","createRequire","dlopen"].includes(n.callee.name || n.callee.property?.name)) facts.push({from:file,kind:n.callee.name || n.callee.property.name,site,expression:source.slice(n.start,n.end)});
    for (const v of Object.values(n)) { if (Array.isArray(v)) todo.push(...v); else if (v && typeof v === "object") todo.push(v); }
  }
}
fs.writeFileSync(output,JSON.stringify({schema:"openclaw-v98-static-import-graph/v1",root,files:[...seen].sort().map((p)=>entries.get(p)),metadata:[...metadata].sort().map((p)=>entries.get(p)),builtins:[...builtins].sort(),edges,unresolved,facts,completeClosureClaimed:false,imageJavaScriptExecuted:false},null,2)+"\n");
console.log(JSON.stringify({files:seen.size,edges:edges.length,unresolved:unresolved.length,workerAndNativeFacts:facts.length,output}));
