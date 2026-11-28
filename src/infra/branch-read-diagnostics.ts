/** Internal per-call telemetry. All wall phases are inclusive and may overlap.
 * nextMs measures native next wall, not SQLite CPU. Lengths are UTF-16 code units.
 * fallbackAvailable=0: navigation projection does not expose fallback provenance.
 */
const fields = [
  "cache",
  "full",
  "tail",
  "tailFallback",
  "fullRows",
  "tailRows",
  "selectedHeadlineRows",
  "branchCount",
  "navigationUtf16CodeUnits",
  "selectedBodyUtf16CodeUnits",
  "nextMs",
  "decodeMs",
  "projectMs",
  "treeInclusiveMs",
  "headlineInclusiveMs",
  "cloneMs",
  "selectedQueryMs",
  "ok",
  "missing",
  "failed",
  "exception",
  "saturated",
  "fallbackAvailable",
] as const;
type Field = (typeof fields)[number];
export type BranchReadAggregate = Readonly<Record<Field, number>>;
export type BranchReadDiagnosticsSink = (aggregate: BranchReadAggregate) => void;
export function createBranchReadDiagnostics() {
  const values = Object.fromEntries(fields.map((key) => [key, 0])) as Record<Field, number>;
  return {
    add(key: Field, value = 1) {
      if (!fields.includes(key) || !Number.isFinite(value) || value < 0) return;
      const sum = values[key] + value;
      if (sum > Number.MAX_SAFE_INTEGER) values.saturated = 1;
      values[key] = Math.min(Number.MAX_SAFE_INTEGER, sum);
    },
    measure<T>(key: Field, action: () => T): T {
      const start = performance.now();
      try {
        return action();
      } finally {
        this.add(key, Math.max(0, performance.now() - start));
      }
    },
    emit(sink: BranchReadDiagnosticsSink) {
      try {
        sink(Object.freeze({ ...values }));
      } catch {
        /* Never replace the read outcome. */
      }
    },
  };
}
export type BranchReadDiagnostics = ReturnType<typeof createBranchReadDiagnostics>;
