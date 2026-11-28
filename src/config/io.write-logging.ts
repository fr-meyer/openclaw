import { isVerbose } from "../global-state.js";
import { isVitestRuntimeEnv } from "../infra/env.js";
import { formatConfigOverwriteLogMessage } from "./io.audit.js";
import type { ConfigIoContext } from "./io.context.js";
import type { ConfigWriteOptions, ReadConfigFileSnapshotInternalResult } from "./io.types.js";

export function createConfigWriteLoggers(params: {
  deps: ConfigIoContext["deps"];
  configPath: string;
  options: ConfigWriteOptions;
  snapshot: ReadConfigFileSnapshotInternalResult["snapshot"];
  previousHash: string | null;
  nextHash: string;
  changedPathCount: number;
  suspiciousReasons: string[];
}) {
  const {
    deps,
    configPath,
    options,
    snapshot,
    previousHash,
    nextHash,
    changedPathCount,
    suspiciousReasons,
  } = params;
  const readTestLogFlag = (name: string) => isVitestRuntimeEnv(deps.env) && deps.env[name] === "1";
  const logConfigOverwrite = () => {
    if (
      !snapshot.exists ||
      options.skipOutputLogs ||
      (isVitestRuntimeEnv(deps.env) && !readTestLogFlag("OPENCLAW_TEST_CONFIG_WRITE_LOG"))
    ) {
      return;
    }
    const testLog = readTestLogFlag("OPENCLAW_TEST_CONFIG_WRITE_LOG");
    if (!isVerbose() && deps.env.OPENCLAW_CONFIG_OVERWRITE_LOG !== "1" && !testLog) {
      return;
    }
    deps.logger.warn(
      formatConfigOverwriteLogMessage({
        configPath,
        previousHash: previousHash ?? null,
        nextHash,
        changedPathCount,
      }),
    );
  };
  const logConfigWriteAnomalies = () => {
    const testLog = readTestLogFlag("OPENCLAW_TEST_CONFIG_WRITE_LOG");
    if (
      suspiciousReasons.length === 0 ||
      options.skipOutputLogs ||
      (isVitestRuntimeEnv(deps.env) && !testLog)
    ) {
      return;
    }
    const showMissingMeta =
      isVerbose() || deps.env.OPENCLAW_CONFIG_WRITE_ANOMALY_LOG === "1" || testLog;
    const visibleReasons = showMissingMeta
      ? suspiciousReasons
      : suspiciousReasons.filter((reason) => reason !== "missing-meta-before-write");
    if (visibleReasons.length > 0) {
      deps.logger.warn(`Config write anomaly: ${configPath} (${visibleReasons.join(", ")})`);
    }
  };

  return { logConfigOverwrite, logConfigWriteAnomalies };
}
