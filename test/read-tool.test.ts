import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { readRange, type ReadToolContext } from "../src/llm/read-tool.js";
import type { RootRecord } from "../src/types.js";
import { tempDir } from "./helpers.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
  dirs.length = 0;
});

function setup(files: Record<string, string>, allowed: string[]): ReadToolContext & { root: string } {
  const root = fs.realpathSync(tempDir("clearance-read-"));
  dirs.push(root);
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body);
  }
  const rootRecord: RootRecord = {
    rootId: "root-1",
    supplied: root,
    realPath: root,
    git: { kind: "none" },
  };
  const config = defaultConfig();
  config.llm.tools.maxLines = 5;
  return {
    root,
    roots: [rootRecord],
    config,
    allowedPaths: new Set(allowed),
    budget: { remaining: 3 },
  };
}

const NUMBERED = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join("\n");

describe("ranged read tool", () => {
  it("returns the requested range with line numbers", () => {
    const ctx = setup({ "app.ts": NUMBERED }, ["app.ts"]);
    const result = readRange({ path: "app.ts", startLine: 3, endLine: 5 }, ctx);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.returnedLines).toBe(3);
    expect(result.truncated).toBe(false);
    expect(result.text).toContain("3: line 3");
    expect(result.text).toContain("5: line 5");
    expect(result.text).not.toContain("6: line 6");
  });

  it("truncates an over-wide range and says so", () => {
    const ctx = setup({ "app.ts": NUMBERED }, ["app.ts"]);
    const result = readRange({ path: "app.ts", startLine: 1, endLine: 25 }, ctx);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // maxLines is 5, so the window is clamped rather than refused.
    expect(result.returnedLines).toBe(5);
    expect(result.truncated).toBe(true);
    expect(result.text).toContain("truncated at maxLines=5");
    expect(result.text).toContain("requested 1-25");
  });

  it("refuses a path with no finding in the batch", () => {
    const ctx = setup({ "app.ts": NUMBERED, "other.ts": NUMBERED }, ["app.ts"]);
    const result = readRange({ path: "other.ts", startLine: 1, endLine: 3 }, ctx);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("does not carry a finding in this batch");
  });

  it("refuses to escape the scan root", () => {
    const ctx = setup({ "app.ts": NUMBERED }, ["../outside.txt", "app.ts"]);
    const result = readRange({ path: "../outside.txt", startLine: 1, endLine: 3 }, ctx);
    expect(result.ok).toBe(false);
  });

  it("refuses a symlink pointing outside the root", () => {
    const outside = fs.realpathSync(tempDir("clearance-read-outside-"));
    dirs.push(outside);
    fs.writeFileSync(path.join(outside, "secret.txt"), "leak\n");
    const ctx = setup({ "app.ts": NUMBERED }, ["link.txt"]);
    fs.symlinkSync(path.join(outside, "secret.txt"), path.join(ctx.root, "link.txt"));
    const result = readRange({ path: "link.txt", startLine: 1, endLine: 1 }, ctx);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("escapes the scan root");
  });

  it("spends and then exhausts the per-batch budget", () => {
    const ctx = setup({ "app.ts": NUMBERED }, ["app.ts"]);
    ctx.budget.remaining = 2;
    expect(readRange({ path: "app.ts", startLine: 1, endLine: 2 }, ctx).ok).toBe(true);
    expect(readRange({ path: "app.ts", startLine: 1, endLine: 2 }, ctx).ok).toBe(true);
    const third = readRange({ path: "app.ts", startLine: 1, endLine: 2 }, ctx);
    expect(third.ok).toBe(false);
    if (third.ok) return;
    expect(third.error).toContain("budget exhausted");
  });

  it("does not spend budget on a refused read", () => {
    const ctx = setup({ "app.ts": NUMBERED }, ["app.ts"]);
    const before = ctx.budget.remaining;
    readRange({ path: "nope.ts", startLine: 1, endLine: 2 }, ctx);
    expect(ctx.budget.remaining).toBe(before);
  });

  it("rejects a start past the end of file", () => {
    const ctx = setup({ "app.ts": NUMBERED }, ["app.ts"]);
    const result = readRange({ path: "app.ts", startLine: 999, endLine: 1000 }, ctx);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("past end of file");
  });

  it("is disabled by default in config", () => {
    const config = defaultConfig();
    expect(config.llm.tools.read).toBe(false);
    expect(config.llm.tools.maxLines).toBe(200);
    expect(config.llm.tools.maxCalls).toBe(8);
  });
});

describe("read tool wiring", () => {
  it("builds a per-batch context and traces every call", async () => {
    const { runValidation } = await import("../src/llm/validate.js");
    const { readRange } = await import("../src/llm/read-tool.js");
    const config = defaultConfig();
    config.llm.enabled = true;
    config.llm.tools = { read: true, maxLines: 5, maxCalls: 2 };

    const root = fs.realpathSync(tempDir("clearance-wire-"));
    dirs.push(root);
    fs.writeFileSync(path.join(root, "app.env"), NUMBERED);
    const roots: RootRecord[] = [
      { rootId: "root-1", supplied: root, realPath: root, git: { kind: "none" } },
    ];

    const records: Array<{ event: string; tool?: { path: string; ok: boolean } }> = [];
    let seenAllowed: string[] = [];

    const runtime = {
      async validateBatch(request: never, _i: string, _r: unknown, tools: never) {
        const ctx = tools as unknown as {
          allowedPaths: Set<string>;
          budget: { remaining: number };
          onCall: (e: Record<string, unknown>) => void;
          roots: RootRecord[];
        };
        seenAllowed = [...ctx.allowedPaths];
        // Mirror what the agents runtime does inside tool execute().
        for (const target of ["app.env", "not-in-batch.env"]) {
          const result = readRange({ path: target, startLine: 1, endLine: 3 }, { ...ctx, config });
          ctx.onCall({ path: target, startLine: 1, endLine: 3, ok: result.ok });
        }
        const req = request as unknown as { batchId: string; clusters: Array<{ clusterId: string }> };
        return {
          batchId: req.batchId,
          verdicts: req.clusters.map((c) => ({
            clusterId: c.clusterId,
            status: "confirmed" as const,
            confidence: 0.9,
            rationale: "ok",
          })),
        };
      },
    };

    await runValidation({
      clusters: [
        {
          clusterId: "C-000001", secretId: "S", presence: "current", rootId: "root-1",
          path: "app.env", lineStart: 1, lineEnd: 1, category: "secret", severity: "high",
          foundBy: ["gitleaks"], notFoundBy: [], occurrenceIds: ["o1"],
          locations: [{ path: "app.env", lineStart: 1, scanners: ["gitleaks"] }],
          effectiveStatus: "open", effectiveSeverity: "high",
        },
      ],
      occurrences: [],
      config,
      runtime: runtime as never,
      instructions: "x",
      onWarning: () => undefined,
      roots,
      trace: { append: (r) => records.push(r as never) },
    });

    // Scoped to the paths carrying a finding in this batch.
    expect(seenAllowed).toEqual(["app.env"]);
    const toolCalls = records.filter((r) => r.event === "tool-call");
    expect(toolCalls).toHaveLength(2);
    expect(toolCalls[0]!.tool).toMatchObject({ path: "app.env", ok: true });
    expect(toolCalls[1]!.tool).toMatchObject({ path: "not-in-batch.env", ok: false });
  });
});
