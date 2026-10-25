// Run with Node's test runner against an isolated or frozen workspace install.
// Synthetic inputs only; the retained v3 compatibility API must remain bounded too.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const packageRequire = createRequire(
  resolve(process.env.ZOD_TEST_PROJECT ?? process.cwd(), "package.json"),
);
const packagePath = packageRequire.resolve("zod/package.json");
assert.equal(packageRequire("zod/package.json").version, "4.6.6");
for (const format of ["esm", "cjs"]) {
  for (const family of ["v4", "v3"]) {
    const z =
      format === "esm"
        ? await import(pathToFileURL(resolve(dirname(packagePath), family, "index.js")).href)
        : packageRequire(`zod/${family}`);
    test(`${format}/${family} bounds collections before visiting children`, async () => {
      for (const kind of ["array-max", "array-exact", "set-max"]) {
        for (const asynchronous of [false, true]) {
          let visits = 0;
          const element = z.string().refine(() => {
            visits++;
            return true;
          });
          const schema =
            kind === "set-max"
              ? z.set(element).max(1)
              : kind === "array-exact"
                ? z.array(element).length(1)
                : z.array(element).max(1);
          const input = kind === "set-max" ? new Set(["first", "second"]) : ["first", "second"];
          const result = asynchronous
            ? await schema.safeParseAsync(input)
            : schema.safeParse(input);
          assert.equal(result.success, false);
          assert.equal(visits, 0);
          assert.equal(result.error.issues[0].code, "too_big");
        }
      }
      let validVisits = 0;
      const valid = z
        .array(
          z.string().transform((value) => {
            validVisits++;
            return value.toUpperCase();
          }),
        )
        .max(1);
      assert.deepEqual(valid.parse(["valid"]), ["VALID"]);
      assert.equal(validVisits, 1);
      let unboundedVisits = 0;
      const unbounded = z.array(
        z.string().refine(() => {
          unboundedVisits++;
          return true;
        }),
      );
      assert.equal(unbounded.safeParse(["one", "two", "three"]).success, true);
      assert.equal(unboundedVisits, 3);
      let minimumVisits = 0;
      const minimum = z
        .array(
          z.string().refine(() => {
            minimumVisits++;
            return true;
          }),
        )
        .min(2);
      assert.equal(minimum.safeParse(["one"]).success, false);
      assert.equal(minimumVisits, 1);
    });
  }
}
