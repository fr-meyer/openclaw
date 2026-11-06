import path from "node:path";

export type LocalMcpServiceSpec = {
  id: string;
  command: string;
  args?: readonly string[];
  cwd: string;
  pidFile: string;
  logFile: string;
  host: string;
  port: number;
};

export type LocalMcpServiceStartPlan = {
  command: string;
  args: string[];
  cwd: string;
  pidFile: string;
  logFile: string;
  detached: true;
};

export type ProcNetListener = {
  addressHex: string;
  port: number;
  state: string;
  family: "ipv4" | "ipv6";
  loopback: boolean;
};

const SERVICE_ID_RE = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const IPV4_LOOPBACK_HEX = /^0100007f$/i;
const IPV6_LOOPBACK_HEX =
  /^(?:00000000000000000000000001000000|00000000000000000000000000000001)$/i;
const DOTENV_ARGUMENT_RE = /^(?:--env-file(?:=|$)|--dotenv(?:=|$))/i;

function assertAbsolutePath(label: string, value: string): void {
  if (!value || !path.isAbsolute(value) || value.includes("\0")) {
    throw new Error(`${label} must be a non-empty absolute path`);
  }
}

export function isLoopbackHost(host: string): boolean {
  const normalized = host
    .trim()
    .toLowerCase()
    .replace(/^\[(.*)\]$/, "$1");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

export function validateLocalMcpServiceSpec(spec: LocalMcpServiceSpec): void {
  if (!SERVICE_ID_RE.test(spec.id)) {
    throw new Error("service id must be a lowercase stable identifier");
  }
  assertAbsolutePath("command", spec.command);
  assertAbsolutePath("cwd", spec.cwd);
  assertAbsolutePath("pidFile", spec.pidFile);
  assertAbsolutePath("logFile", spec.logFile);
  if (!isLoopbackHost(spec.host)) {
    throw new Error("service host must be loopback-only");
  }
  if (!Number.isInteger(spec.port) || spec.port < 1 || spec.port > 65535) {
    throw new Error("service port must be an integer between 1 and 65535");
  }
  for (const arg of spec.args ?? []) {
    if (arg.includes("\0")) {
      throw new Error("service arguments must not contain NUL bytes");
    }
    const basename = path.basename(arg).toLowerCase();
    if (DOTENV_ARGUMENT_RE.test(arg) || basename === ".env" || basename.startsWith(".env.")) {
      throw new Error("service arguments must not load .env files");
    }
  }
}

export function buildLocalMcpServiceStartPlan(spec: LocalMcpServiceSpec): LocalMcpServiceStartPlan {
  validateLocalMcpServiceSpec(spec);
  return {
    command: spec.command,
    args: [...(spec.args ?? [])],
    cwd: spec.cwd,
    pidFile: spec.pidFile,
    logFile: spec.logFile,
    detached: true,
  };
}

export function parsePidFile(raw: string): number {
  const trimmed = raw.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new Error("PID file must contain one positive decimal integer");
  }
  const pid = Number(trimmed);
  if (!Number.isSafeInteger(pid) || pid <= 1) {
    throw new Error("PID file does not contain a controllable process id");
  }
  return pid;
}

export function parseProcCmdline(raw: Buffer | string): string[] {
  const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : raw;
  const argv = text.split("\0");
  if (argv.at(-1) === "") {
    argv.pop();
  }
  return argv;
}

export function assertProcessIdentity(
  rawCmdline: Buffer | string,
  plan: Pick<LocalMcpServiceStartPlan, "command" | "args">,
): void {
  const argv = parseProcCmdline(rawCmdline);
  if (argv[0] !== plan.command) {
    throw new Error("process executable does not match the supervised command");
  }
  if (argv.length !== plan.args.length + 1) {
    throw new Error("process argument count does not match the supervised command");
  }
  for (const [index, expected] of plan.args.entries()) {
    if (argv[index + 1] !== expected) {
      throw new Error("process arguments do not match the supervised command");
    }
  }
}

function listenerIsLoopback(addressHex: string, family: "ipv4" | "ipv6"): boolean {
  return family === "ipv4"
    ? IPV4_LOOPBACK_HEX.test(addressHex)
    : IPV6_LOOPBACK_HEX.test(addressHex);
}

export function parseProcNetTcp(raw: string, family: "ipv4" | "ipv6"): ProcNetListener[] {
  const listeners: ProcNetListener[] = [];
  for (const line of raw.split(/\r?\n/u).slice(1)) {
    const fields = line.trim().split(/\s+/u);
    if (fields.length < 4) {
      continue;
    }
    const [addressHex, portHex] = (fields[1] ?? "").split(":");
    const state = fields[3]?.toUpperCase() ?? "";
    if (!addressHex || !portHex || !/^[0-9a-f]+$/iu.test(portHex)) {
      continue;
    }
    const port = Number.parseInt(portHex, 16);
    listeners.push({
      addressHex,
      port,
      state,
      family,
      loopback: listenerIsLoopback(addressHex, family),
    });
  }
  return listeners;
}

export function assertOnlyLoopbackListeners(options: {
  port: number;
  tcp4: string;
  tcp6: string;
}): ProcNetListener[] {
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error("port must be an integer between 1 and 65535");
  }
  const listeners = [
    ...parseProcNetTcp(options.tcp4, "ipv4"),
    ...parseProcNetTcp(options.tcp6, "ipv6"),
  ].filter((entry) => entry.port === options.port && entry.state === "0A");
  if (listeners.length === 0) {
    throw new Error("no listening socket was found for the service port");
  }
  if (listeners.some((entry) => !entry.loopback)) {
    throw new Error("service port is exposed on a non-loopback address");
  }
  return listeners;
}

export async function probeLocalMcpHealth(
  spec: LocalMcpServiceSpec,
  options: {
    path?: string;
    timeoutMs?: number;
    fetchImpl?: typeof fetch;
  } = {},
): Promise<{ ok: true; status: number; url: string }> {
  validateLocalMcpServiceSpec(spec);
  const healthPath = options.path ?? "/healthz";
  if (
    !healthPath.startsWith("/") ||
    healthPath.startsWith("//") ||
    healthPath.includes("?") ||
    healthPath.includes("#") ||
    healthPath.includes("\0")
  ) {
    throw new Error("health probe path must be an absolute URL path without query or fragment");
  }
  const timeoutMs = options.timeoutMs ?? 2_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
    throw new Error("health probe timeout must be an integer between 1 and 30000 milliseconds");
  }
  const host = spec.host === "::1" ? "[::1]" : "127.0.0.1";
  const url = `http://${host}:${spec.port}${healthPath}`;
  const response = await (options.fetchImpl ?? fetch)(url, {
    method: "GET",
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`health probe failed with HTTP ${response.status}`);
  }
  return { ok: true, status: response.status, url };
}

export function redactServiceLogLine(line: string): string {
  return line
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/=-]+/giu, "$1 [redacted]")
    .replace(
      /\b(client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|password)\b(\s*[:=]\s*)([^\s,;]+)/giu,
      "$1$2[redacted]",
    )
    .replace(/\b(Authorization)(\s*:\s*)([^\r\n]+)/giu, "$1$2[redacted]");
}
