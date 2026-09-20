import { classifierProgress, type ClassifierProgress } from "../progress.js";
import { spawn } from "node:child_process";
import type { ClassifierConfig } from "./config.js";
import { childErrorCode } from "./protocol.js";

/** Bounded pipes, fixed failures, no inherited credentials, no shell. */
export async function invokeClassifier(
  config: ClassifierConfig,
  input: Buffer,
  env: NodeJS.ProcessEnv,
  signal?: AbortSignal,
  onProgress?: (event: ClassifierProgress) => void,
): Promise<Buffer> {
  if (input.length > config.maxInputBytes) throw new Error("input-limit");
  if (signal?.aborted) throw new Error("cancelled");
  return new Promise((resolve, reject) => {
    const child = spawn(config.executable, config.args, {
      env,
      cwd: "/",
      stdio: ["pipe", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    let failure: string | undefined;
    let inputFailed = false;
    let length = 0,
      stderrLength = 0;
    const chunks: Buffer[] = [];
    const kill = () => {
      try {
        if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        /* already reaped */
      }
    };
    const fail = (reason: string) => {
      failure ??= reason;
      kill();
    };
    const abort = () => fail("cancelled");
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => {
      fail("timeout");
      // Descendants must not hold pipes open beyond the configured deadline.
      child.stdout.destroy();
      child.stderr.destroy();
      child.stdin.destroy();
    }, config.timeoutMs);
    child.on("error", () => fail("launch-failed"));
    child.stdin.on("error", (error: NodeJS.ErrnoException) => {
      inputFailed = true;
      // Early rejection may close stdin before it emits its fixed error envelope.
      // Keep draining bounded output until exit; the existing deadline still applies.
      if (error.code !== "EPIPE") fail("input-failed");
    });
    child.stdout.on("error", () => fail("output-failed"));
    child.stderr.on("error", () => fail("output-failed"));
    child.stdout.on("data", (chunk: Buffer) => {
      length += chunk.length;
      if (length > config.maxOutputBytes) fail("output-limit");
      else chunks.push(chunk);
    });
    let stderrPending = Buffer.alloc(0),
      progressRecords = 0;
    const acceptLine = (line: Buffer) => {
      const event = line.length <= 1024 ? classifierProgress(line.toString("utf8")) : undefined;
      if (event && ++progressRecords <= 32770) {
        try {
          onProgress?.(event);
        } catch {
          /* display is best effort */
        }
      } else {
        stderrLength += line.length + 1;
        if (stderrLength > config.maxStderrBytes || progressRecords > 32770) fail("stderr-limit");
      }
    };
    child.stderr.on("data", (chunk: Buffer) => {
      let start = 0;
      for (let i = 0; i < chunk.length; i++) {
        if (chunk[i] !== 10) continue;
        const line = Buffer.concat([stderrPending, chunk.subarray(start, i)]);
        acceptLine(line);
        stderrPending = Buffer.alloc(0);
        start = i + 1;
      }
      stderrPending = Buffer.concat([stderrPending, chunk.subarray(start)]);
      if (stderrPending.length > 1024) {
        stderrLength += stderrPending.length;
        stderrPending = Buffer.alloc(0);
        if (stderrLength > config.maxStderrBytes) fail("stderr-limit");
      }
    });
    child.on("close", (code) => {
      if (stderrPending.length) acceptLine(stderrPending);
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      kill(); // also reap any surviving children in the process group
      if (failure) {
        reject(new Error(failure));
        return;
      }
      const output = Buffer.concat(chunks, length);
      if (code !== 0) {
        const childCode = childErrorCode(output);
        reject(new Error(childCode ? `child-${childCode}` : "process-failed"));
      } else if (inputFailed) reject(new Error("input-failed"));
      else resolve(output);
    });
    if (signal?.aborted) abort();
    child.stdin.end(input);
  });
}
