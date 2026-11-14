import fs from 'node:fs';
import path from 'node:path';
// Vitest reporter lifecycle: testCases are actual reported test cases, not expect-call counts.
export function validateInventory(expected, modules, unhandledErrors, root) {
  if (unhandledErrors.length || modules.length !== expected.length) throw Error('errors or wrong file count');
  const seen = new Set();
  const inventory = [];
  for (const module of modules) {
    const file = path.relative(root, module.moduleId).split(path.sep).join('/');
    if (!expected.includes(file) || seen.has(file) || module.state() !== 'passed') throw Error('unexpected/duplicate/nonpassed file');
    seen.add(file);
    const tests = [...module.children.allTests()];
    if (!tests.length) throw Error('zero testCases');
    const names = new Set();
    for (const test of tests) {
      if (test.result().state !== 'passed' || names.has(test.fullName)) throw Error('skip/todo/failure/duplicate assertion');
      names.add(test.fullName);
    }
    inventory.push({ file, testCases: tests.map(t => t.fullName), state: 'passed' });
  }
  return inventory;
}
export default class InventoryReporter {
  onInit(vitest) { this.root = vitest.config.root; }
  onTestRunEnd(modules, errors, reason) {
    if (reason !== 'passed') throw Error('run interrupted or failed');
    const expected = JSON.parse(process.env.B_EXPECTED_TESTS);
    const files = modules.map(m => path.relative(process.cwd(), m.moduleId).split(path.sep).join('/'));
    if (!files.length || files.some(f => !expected.includes(f))) throw Error('no tests or unexpected routed file');
    const inventory = validateInventory(files, modules, errors, process.cwd());
    for (const entry of inventory) {
      fs.writeFileSync(path.join(process.env.B_INVENTORY_DIR, encodeURIComponent(entry.file)+'.json'), JSON.stringify(entry), {flag:'wx'});
    }
  }
}
