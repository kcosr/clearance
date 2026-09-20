import { spawn } from "node:child_process";

export const SCANNER_TIMEOUT_MS = 120_000;
export const SCANNER_MAX_STDOUT_BYTES = 8_000_000;
export const SCANNER_MAX_REPORT_BYTES = 16_000_000;
export const SCANNER_MAX_FINDINGS = 10_000;
export const VERSION_TIMEOUT_MS = 5_000;

export type CommandResult = {
  exitCode: number | null;
  stdout: Buffer;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  missing: boolean;
};

export function runCommand(
  bin: string,
  args: string[],
  options: {
    cwd?: string;
    timeoutMs: number;
    maxStdoutBytes: number;
    env?: NodeJS.ProcessEnv;
  },
): Promise<CommandResult> {
  return new Promise((resolve) => {
    let stdout = Buffer.alloc(0);
    let stderr = "";
    let truncated = false;
    let timedOut = false;
    let settled = false;

    const child = spawn(bin, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const finish = (result: CommandResult): void => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    child.on("error", (error) => {
      const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
      finish({
        exitCode: null,
        stdout,
        stderr: missing ? "" : String(error),
        timedOut: false,
        truncated,
        missing,
      });
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, options.timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdout.length >= options.maxStdoutBytes) {
        truncated = true;
        return;
      }
      const room = options.maxStdoutBytes - stdout.length;
      stdout = Buffer.concat([stdout, chunk.subarray(0, room)]);
      if (chunk.length > room) truncated = true;
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length >= 64_000) return;
      stderr += chunk.toString("utf8").slice(0, 64_000 - stderr.length);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      finish({
        exitCode: code,
        stdout,
        stderr,
        timedOut,
        truncated,
        missing: false,
      });
    });
  });
}

export type VersionCheck =
  | { ok: true; version: string; warn?: string }
  | { ok: false; error: string };

export function classifyVersion(
  raw: string,
  minimum: { major: number; minor: number; patch: number },
  tested: { major: number; minor: number; patch: number },
  label: string,
  parse: (text: string) => { major: number; minor: number; patch: number } | undefined,
  compare: (
    a: { major: number; minor: number; patch: number },
    b: { major: number; minor: number; patch: number },
  ) => number,
  format: (v: { major: number; minor: number; patch: number }) => string,
): VersionCheck {
  const version = parse(raw);
  if (!version) return { ok: false, error: "unsupported-version" };
  if (compare(version, minimum) < 0) return { ok: false, error: "unsupported-version" };
  const formatted = format(version);
  if (compare(version, tested) > 0) {
    return {
      ok: true,
      version: formatted,
      warn: `${label} ${formatted} is newer than tested ${format(tested)}`,
    };
  }
  return { ok: true, version: formatted };
}
