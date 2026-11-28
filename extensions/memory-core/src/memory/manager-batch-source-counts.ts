import type { MemorySource } from "openclaw/plugin-sdk/memory-core-host-engine-storage";

export function countBatchSources(items: Array<{ source: MemorySource }>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    counts[item.source] = (counts[item.source] ?? 0) + 1;
  }
  return counts;
}

export function formatBatchSourceCounts(counts: Record<string, number>): string {
  return (
    Object.entries(counts)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([source, count]) => `${source}=${count}`)
      .join(",") || "none"
  );
}
