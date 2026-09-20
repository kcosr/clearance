import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect } from "vitest";
import { runClearance, type RunOptions } from "../src/scan.js";
import type { ScanResult } from "../src/types.js";

export const SLACK_TOKEN = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx";
export const SLACK_LINE = `SLACK_BOT_TOKEN=${SLACK_TOKEN}\n`;
export const STRIPE_LIVE = "sk_live_abcdefghijklmnopqrstuvwx123456";
export const PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";

export function tempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function writeTree(root: string, files: Record<string, string | Buffer>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}

export function writeZip(dest: string, entries: Record<string, string>): void {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const script = `
import zipfile, sys, json
dest, raw = sys.argv[1], sys.argv[2]
entries = json.loads(raw)
with zipfile.ZipFile(dest, "w") as z:
    for name, text in entries.items():
        z.writestr(name, text)
`;
  execFileSync("python3", ["-c", script, dest, JSON.stringify(entries)]);
}

export function git(cwd: string, args: string[], env: NodeJS.ProcessEnv = {}): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.com",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.com",
      GIT_AUTHOR_DATE: "2024-01-01T00:00:00 +0000",
      GIT_COMMITTER_DATE: "2024-01-01T00:00:00 +0000",
      ...env,
    },
  });
}

export function initRepo(cwd: string): void {
  git(cwd, ["init", "-b", "main"]);
  git(cwd, ["config", "user.email", "t@example.com"]);
  git(cwd, ["config", "user.name", "t"]);
}

export async function runOn(
  roots: string | string[],
  args: string[] = [],
  extra: Partial<RunOptions> = {},
): Promise<{ result: ScanResult; stdout: string; stderr: string }> {
  const list = Array.isArray(roots) ? roots : [roots];
  const cwd = extra.cwd ?? (list.length === 1 ? list[0]! : path.dirname(list[0]!));
  let stdout = "";
  let stderr = "";
  const result = await runClearance({
    argv: [...args, ...list],
    cwd,
    stdout: {
      write: (chunk) => {
        stdout += chunk;
      },
    },
    stderr: {
      write: (chunk) => {
        stderr += chunk;
      },
    },
    ...extra,
  });
  return { result, stdout, stderr };
}

export function readArtifacts(result: ScanResult): {
  manifest: string;
  markdown: string;
  html: string;
} {
  if (!result.artifacts) throw new Error("Expected report files");
  return {
    manifest: fs.readFileSync(result.artifacts.manifest, "utf8"),
    markdown: fs.readFileSync(result.artifacts.markdown, "utf8"),
    html: fs.readFileSync(result.artifacts.html, "utf8"),
  };
}

export function assertNoSecretLeaks(...texts: string[]): void {
  for (const text of texts) {
    expect(text).not.toContain("xoxb-");
    expect(text).not.toContain("sk_live_");
    expect(text).not.toContain(PEM_HEADER);
    expect(text).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  }
}

export function assertNoFindingAbsolutes(manifest: string, markdown: string, html: string): void {
  const parsed = JSON.parse(manifest) as {
    occurrences: Array<{ path: string }>;
    clusters: Array<{ path: string }>;
  };
  for (const row of [...parsed.occurrences, ...parsed.clusters]) {
    expect(row.path.startsWith("/")).toBe(false);
    expect(row.path).not.toContain("/home/");
  }
  expect(markdown).not.toMatch(/\/home\/[A-Za-z0-9._-]+\//);
  expect(html).not.toMatch(/\/home\/[A-Za-z0-9._-]+\//);
}

export function detector(
  result: ScanResult,
  name: string,
): NonNullable<ScanResult["detectors"][number]> {
  const found = result.detectors.find((item) => item.name === name);
  expect(found).toBeTruthy();
  return found!;
}
