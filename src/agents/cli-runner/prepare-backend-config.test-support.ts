import type { CliBackendPlugin } from "../../plugins/cli-backend.types.js";

export function createArgBackendConfig(
  command: string,
  args = ["--print"],
  output: "text" | "json" = "text",
): CliBackendPlugin["config"] {
  return { command, args, output, input: "arg", sessionMode: "existing" };
}

export function createJsonlStdinBackendConfig(command: string): CliBackendPlugin["config"] {
  return {
    command,
    args: ["--print"],
    output: "jsonl",
    input: "stdin",
    sessionMode: "existing",
  };
}
