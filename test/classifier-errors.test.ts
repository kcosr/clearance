import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_CLASSIFIER, type ClassifierConfig } from "../src/classifier/config.js";
import { invokeClassifier } from "../src/classifier/process.js";
import {
  CHILD_ERROR_CODES,
  childErrorCode,
  response,
  strictJson,
} from "../src/classifier/protocol.js";

const envelope = (code = "provider_refused") => ({
  version: 2,
  status: "error",
  code,
});
const temp: string[] = [];
afterEach(() => {
  for (const dir of temp.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});
function config(source: string): ClassifierConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-child-error-"));
  temp.push(dir);
  const script = path.join(dir, "error.cjs");
  fs.writeFileSync(script, source);
  return {
    ...structuredClone(DEFAULT_CLASSIFIER),
    executable: process.execPath,
    args: [script],
    timeoutMs: 2000,
  };
}

describe("fixed external classifier failure envelopes", () => {
  it.each(CHILD_ERROR_CODES)("preserves %s on nonzero exit", async (code) => {
    const c = config(
      `process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(${JSON.stringify(JSON.stringify(envelope(code)))});process.exitCode=3;});`,
    );
    await expect(invokeClassifier(c, Buffer.from("input"), {})).rejects.toThrow(`child-${code}`);
  });
  it("waits for the structured error after an early stdin EPIPE", async () => {
    const c = config(
      `require('node:fs').closeSync(0);setTimeout(()=>{process.stdout.write(${JSON.stringify(JSON.stringify(envelope("configuration_error")))});process.exitCode=2;},100);`,
    );
    await expect(invokeClassifier(c, Buffer.alloc(4 * 1024 * 1024), {})).rejects.toThrow(
      "child-configuration_error",
    );
  });

  it.each(CHILD_ERROR_CODES)("rejects obsolete identity-bearing %s envelopes", (code) => {
    expect(
      childErrorCode(
        Buffer.from(
          JSON.stringify({
            ...envelope(code),
            configuration_id: `sha256:${"0".repeat(64)}`,
          }),
        ),
      ),
    ).toBeUndefined();
  });
  it.each([0, 3])(
    "classifies EPIPE without accepted output by exit status %s",
    async (exitCode) => {
      const c = config(
        `require('node:fs').closeSync(0);setTimeout(()=>{process.stdout.write('unaccepted');process.exitCode=${exitCode};},100);`,
      );
      await expect(invokeClassifier(c, Buffer.alloc(4 * 1024 * 1024), {})).rejects.toThrow(
        exitCode === 0 ? "input-failed" : "process-failed",
      );
    },
  );
  it("still bounds the lifetime of a child that closes stdin without exiting", async () => {
    const c = config("require('node:fs').closeSync(0);setInterval(()=>{},1000);");
    c.timeoutMs = 150;
    await expect(invokeClassifier(c, Buffer.alloc(4 * 1024 * 1024), {})).rejects.toThrow("timeout");
  });
  it.each(["timeout", "output-limit", "stderr-limit", "cancelled"])(
    "keeps %s authoritative over an error envelope",
    async (reason) => {
      const code = `process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(${JSON.stringify(JSON.stringify(envelope()))});${reason === "output-limit" ? "process.stdout.write('x'.repeat(10000));" : reason === "stderr-limit" ? "process.stderr.write('x'.repeat(10000));" : ""}setInterval(()=>{},1000);});`;
      const c = config(code);
      c.maxOutputBytes = 500;
      c.maxStderrBytes = 500;
      if (reason === "timeout") c.timeoutMs = 150;
      const control = new AbortController();
      const timer = reason === "cancelled" ? setTimeout(() => control.abort(), 150) : undefined;
      try {
        await expect(invokeClassifier(c, Buffer.from("input"), {}, control.signal)).rejects.toThrow(
          reason,
        );
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
  );
  it("never promotes malformed, foreign or arbitrary child diagnostics", () => {
    const valid = JSON.stringify(envelope());
    for (const wire of [
      valid + " {}",
      valid.replace('"version":2', '"version":2,"version":2'),
      JSON.stringify({ ...envelope(), configuration_id: `sha256:${"0".repeat(64)}` }),
      JSON.stringify({ ...envelope(), code: "private source leaked here" }),
      JSON.stringify({ ...envelope(), code: "configuration_mismatch" }),
      JSON.stringify({ ...envelope(), message: "sensitive" }),
      JSON.stringify({ ...envelope(), findings: [] }),
      JSON.stringify({ ...envelope(), version: 1 }),
      JSON.stringify({ ...envelope(), status: "complete" }),
    ])
      expect(childErrorCode(Buffer.from(wire))).toBeUndefined();
  });
  it("retains generic failure for nonzero exits without a valid error envelope", async () => {
    const c = config(
      `process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(${JSON.stringify(JSON.stringify({ ...envelope(), code: "private details" }))});process.exitCode=3;});`,
    );
    await expect(invokeClassifier(c, Buffer.from("input"), {})).rejects.toThrow("process-failed");
  });
  it("error envelopes cannot become successful findings on exit zero", async () => {
    const c = config(
      `process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(${JSON.stringify(JSON.stringify(envelope()))});});`,
    );
    const output = await invokeClassifier(c, Buffer.from("input"), {});
    expect(() => response(output, 10, 1000)).toThrow("invalid-response");
  });
});

describe("strict JSON failure normalization", () => {
  it.each([
    Buffer.from([0xff]),
    Buffer.from('"private\\qvalue"'),
    Buffer.from('"raw\ncontrol"'),
    Buffer.from('{"secret":}'),
    Buffer.from('"\\ud800"'),
    Buffer.from('{"x":1,"\\u0078":2}'),
  ])("normalizes decoder and parser failures", (bytes) => {
    expect(() => strictJson(bytes)).toThrow(/^invalid-response$/);
  });
});
