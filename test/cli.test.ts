import fs from "node:fs";
import { expect, it } from "vitest";
import { runClearance } from "../src/scan.js";
import { tempDir } from "./helpers.js";

it("prints version and help without scanning", async () => {
  let version = "";
  const v = await runClearance({
    argv: ["--version"],
    stdout: {
      write: (chunk) => {
        version += chunk;
      },
    },
    stderr: { write: () => undefined },
  });
  expect(v.exitCode).toBe(0);
  expect(version).toMatch(/clearance 0\.1\.0/);

  let help = "";
  const h = await runClearance({
    argv: ["--help"],
    stdout: {
      write: (chunk) => {
        help += chunk;
      },
    },
    stderr: { write: () => undefined },
  });
  expect(h.exitCode).toBe(0);
  expect(help).toContain("--fail-on");
});

it("emits full JSON results on scan errors", async () => {
  const cwd = tempDir("clearance-cli-");
  let stdout = "";
  const result = await runClearance({
    argv: ["--json", "--no-gitleaks", "--no-trufflehog", "--no-native"],
    cwd,
    stdout: {
      write: (chunk) => {
        stdout += chunk;
      },
    },
    stderr: { write: () => undefined },
  });
  expect(result.outcome).toBe("error");
  const parsed = JSON.parse(stdout) as { outcome: string; clusters?: unknown };
  expect(parsed.outcome).toBe("error");
  expect(parsed.clusters).toEqual([]);
  fs.rmSync(cwd, { recursive: true, force: true });
});
