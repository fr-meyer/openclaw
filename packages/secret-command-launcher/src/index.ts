import path from "node:path";

export type SecretEnvironmentBinding = {
  name: string;
  value: string;
};

export type SecretCommandLaunchInput = {
  command: string;
  args?: readonly string[];
  cwd?: string;
  baseEnv?: Readonly<Record<string, string | undefined>>;
  secrets: readonly SecretEnvironmentBinding[];
};

export type SecretCommandLaunchPlan = {
  command: string;
  args: string[];
  cwd?: string;
  env: Record<string, string>;
  secretEnvironmentNames: string[];
};

const ENVIRONMENT_NAME_RE = /^[A-Z_][A-Z0-9_]*$/;

function assertSafeString(label: string, value: string): void {
  if (!value || value.includes("\0")) {
    throw new Error(`${label} must be non-empty and must not contain NUL bytes`);
  }
}

export function buildSecretCommandLaunchPlan(
  input: SecretCommandLaunchInput,
): SecretCommandLaunchPlan {
  assertSafeString("command", input.command);
  if (!path.isAbsolute(input.command)) {
    throw new Error("command must be an absolute path");
  }
  if (input.cwd !== undefined) {
    assertSafeString("cwd", input.cwd);
    if (!path.isAbsolute(input.cwd)) {
      throw new Error("cwd must be an absolute path");
    }
  }

  const args = [...(input.args ?? [])];
  for (const arg of args) {
    if (arg.includes("\0")) {
      throw new Error("command arguments must not contain NUL bytes");
    }
  }

  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.baseEnv ?? {})) {
    if (!ENVIRONMENT_NAME_RE.test(name)) {
      throw new Error(`invalid base environment name: ${name}`);
    }
    if (value?.includes("\0")) {
      throw new Error(`base environment ${name} must not contain NUL bytes`);
    }
    if (value !== undefined) {
      env[name] = value;
    }
  }

  const seen = new Set<string>();
  for (const secret of input.secrets) {
    if (!ENVIRONMENT_NAME_RE.test(secret.name)) {
      throw new Error(`invalid secret environment name: ${secret.name}`);
    }
    if (seen.has(secret.name)) {
      throw new Error(`duplicate secret environment name: ${secret.name}`);
    }
    if (Object.hasOwn(input.baseEnv ?? {}, secret.name)) {
      throw new Error(`secret environment name conflicts with base environment: ${secret.name}`);
    }
    assertSafeString(`secret ${secret.name}`, secret.value);
    if (
      input.command.includes(secret.value) ||
      input.cwd?.includes(secret.value) ||
      args.some((arg) => arg.includes(secret.value))
    ) {
      throw new Error(`secret ${secret.name} must not appear in command arguments or paths`);
    }
    seen.add(secret.name);
    env[secret.name] = secret.value;
  }

  return {
    command: input.command,
    args,
    ...(input.cwd === undefined ? {} : { cwd: input.cwd }),
    env,
    secretEnvironmentNames: [...seen].sort(),
  };
}

export function summarizeSecretCommandLaunchPlan(plan: SecretCommandLaunchPlan): {
  command: string;
  args: string[];
  cwd?: string;
  environmentNames: string[];
  secretEnvironmentNames: string[];
} {
  return {
    command: plan.command,
    args: [...plan.args],
    ...(plan.cwd === undefined ? {} : { cwd: plan.cwd }),
    environmentNames: Object.keys(plan.env).sort(),
    secretEnvironmentNames: [...plan.secretEnvironmentNames],
  };
}

export function redactResolvedSecrets(
  text: string,
  secrets: readonly SecretEnvironmentBinding[],
): string {
  const values = [...new Set(secrets.map((secret) => secret.value).filter(Boolean))].sort(
    (left, right) => right.length - left.length,
  );
  let redacted = text;
  for (const value of values) {
    redacted = redacted.split(value).join("[redacted]");
  }
  return redacted;
}
