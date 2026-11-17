import fs from "node:fs";
import { prepareInert, prepareFinal, run } from "../no-copy-layout.mjs";
const [mode, file, target, image] = process.argv.slice(2),
  config = JSON.parse(fs.readFileSync(file));
try {
  if (mode === "inert") console.log(JSON.stringify(prepareInert(config, target)));
  else if (mode === "compose") {
    const r = prepareFinal(config, target);
    console.log(JSON.stringify({ receiptSha256: r.receiptSha256, buildArgv: r.buildArgv }));
  } else if (mode === "runtime") {
    const r = run(config, target, image);
    process.stdout.write(r.stdout);
    process.stderr.write(r.stderr);
    process.exitCode = r.status ?? 1;
  } else throw Error("mode inert|compose|runtime required");
} catch (e) {
  console.error(JSON.stringify({ status: "PHASE1_FAILED_CLOSED", error: e.message }));
  process.exitCode = 1;
}
