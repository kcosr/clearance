import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig, loadConfig } from "../src/config.js";
import { parseArgs } from "../src/cli-parse.js";
import { createConstantRuntime } from "../src/llm/runtime.js";
import {
  createTraceSink,
  JsonlTraceSink,
  NoopTraceSink,
  writeTraceHtml,
  type TraceRecord,
} from "../src/llm/trace.js";
import { renderTraceHtml } from "../src/llm/trace-html.js";
import { runValidation } from "../src/llm/validate.js";
import type { ValidatorRuntime } from "../src/llm/runtime.js";
import type { Cluster, Occurrence } from "../src/types.js";
import { runOn, tempDir, writeTree } from "./helpers.js";

const cluster: Cluster = {
  clusterId: "C-000001",
  secretId: "H:abc",
  presence: "current",
  rootId: "root-1",
  path: "app.env",
  lineStart: 1,
  lineEnd: 1,
  category: "slack-token",
  severity: "high",
  foundBy: ["gitleaks"],
  notFoundBy: [],
  occurrenceIds: ["o1"],
  locations: [{ path: "app.env", lineStart: 1, scanners: ["gitleaks"] }],
  candidateFingerprint: "abc",
  effectiveStatus: "open",
  effectiveSeverity: "high",
};

const occurrence: Occurrence = {
  occurrenceId: "o1",
  scanner: "gitleaks",
  rootId: "root-1",
  path: "app.env",
  lineStart: 1,
  lineEnd: 1,
  ruleId: "slack-bot-token",
  category: "slack-token",
  severity: "high",
  source: { kind: "workingTree" },
  extraction: "exact",
  candidate: "xoxb-secret-value",
};

function collectingSink(): { sink: { append(r: TraceRecord): void }; records: TraceRecord[] } {
  const records: TraceRecord[] = [];
  return { sink: { append: (r) => records.push(r) }, records };
}

describe("llm trace", () => {
  it("is disabled by default and enabled by a path", () => {
    expect(defaultConfig().llm.traceFile).toBe("");
    expect(defaultConfig().llm.traceDetail).toBe("metadata");
    expect(createTraceSink("")).toBeInstanceOf(NoopTraceSink);
    expect(createTraceSink("/tmp/x.jsonl")).toBeInstanceOf(JsonlTraceSink);
  });

  it("is configurable by flag and environment", () => {
    expect(parseArgs(["--llm-trace", "/tmp/t.jsonl"]).llmTrace).toBe("/tmp/t.jsonl");
    expect(parseArgs(["--llm-trace-detail", "full"]).llmTraceDetail).toBe("full");
    expect(() => parseArgs(["--llm-trace-detail", "wat"])).toThrow(/metadata\|full/);
    const env = loadConfig(
      { roots: [] },
      { CLEARANCE_LLM_TRACE: "/tmp/e.jsonl", CLEARANCE_LLM_TRACE_DETAIL: "full" },
    );
    expect(env.llm.traceFile).toBe("/tmp/e.jsonl");
    expect(env.llm.traceDetail).toBe("full");
  });

  it("places a relative configured trace inside the report output directory", async () => {
    const root = tempDir("clearance-trace-root-");
    const admin = tempDir("clearance-trace-config-");
    const configFile = path.join(admin, "config.toml");
    writeTree(root, { "payload.exe": "MZ fake executable\n" });
    fs.writeFileSync(
      configFile,
      `
[detectors.gitleaks]
enabled = false
history = false

[detectors.trufflehog]
enabled = false
history = false

[llm]
enabled = true
traceFile = "llm-trace.jsonl"
traceDetail = "full"

[report]
outputDir = "scan-output"
`,
    );

    try {
      await runOn(root, ["--config", configFile], {
        llmRuntime: createConstantRuntime("false_positive"),
      });
      expect(fs.existsSync(path.join(root, "scan-output", "llm-trace.jsonl"))).toBe(true);
      expect(fs.existsSync(path.join(root, "scan-output", "llm-trace.html"))).toBe(true);
      expect(fs.existsSync(path.join(root, "llm-trace.jsonl"))).toBe(false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(admin, { recursive: true, force: true });
    }
  });

  it("writes one 0600 JSONL record per batch attempt", () => {
    const dir = tempDir("clearance-trace-");
    const file = path.join(dir, "nested", "trace.jsonl");
    const sink = new JsonlTraceSink(file);
    sink.append({
      ts: "2026-01-01T00:00:00.000Z",
      event: "batch-attempt",
      batchId: "B-0001",
      attempt: 0,
      repair: false,
      clusterIds: ["C-000001"],
      durationMs: 5,
      accepted: true,
    });
    sink.append({
      ts: "2026-01-01T00:00:01.000Z",
      event: "batch-attempt",
      batchId: "B-0001",
      attempt: 1,
      repair: true,
      clusterIds: ["C-000001"],
      durationMs: 6,
      accepted: false,
      diagnostics: ["unknown clusterId"],
    });
    const lines = fs.readFileSync(file, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1]!).repair).toBe(true);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("records a rejected attempt and its repair, without secrets at metadata detail", async () => {
    const config = defaultConfig();
    config.llm.enabled = true;
    config.llm.maxRepairs = 1;
    const { sink, records } = collectingSink();
    let call = 0;
    const runtime: ValidatorRuntime = {
      async validateBatch(request) {
        call += 1;
        if (call === 1) {
          return {
            batchId: request.batchId,
            verdicts: [
              { clusterId: "C-999999", status: "confirmed", confidence: 1, rationale: "bad" },
            ],
          } as never;
        }
        return {
          batchId: request.batchId,
          verdicts: request.clusters.map((item) => ({
            clusterId: item.clusterId,
            status: "confirmed" as const,
            confidence: 0.9,
            rationale: "ok",
          })),
        };
      },
    };

    await runValidation({
      clusters: [cluster],
      occurrences: [occurrence],
      config,
      runtime,
      instructions: "test",
      onWarning: () => undefined,
      trace: sink,
    });

    expect(records).toHaveLength(2);
    expect(records[0]!.accepted).toBe(false);
    expect(records[0]!.diagnostics?.join(" ")).toContain("C-999999");
    expect(records[0]!.repair).toBe(false);
    expect(records[1]!.accepted).toBe(true);
    expect(records[1]!.repair).toBe(true);
    // metadata detail must not carry the request or the raw response
    for (const record of records) {
      expect(record.request).toBeUndefined();
      expect(record.response).toBeUndefined();
      expect(JSON.stringify(record)).not.toContain("xoxb-");
    }
  });

  it("records request and response at full detail", async () => {
    const config = defaultConfig();
    config.llm.enabled = true;
    config.llm.traceDetail = "full";
    const { sink, records } = collectingSink();
    const runtime: ValidatorRuntime = {
      async validateBatch(request) {
        return {
          batchId: request.batchId,
          verdicts: request.clusters.map((item) => ({
            clusterId: item.clusterId,
            status: "confirmed" as const,
            confidence: 0.9,
            rationale: "ok",
          })),
        };
      },
    };
    await runValidation({
      clusters: [cluster],
      occurrences: [occurrence],
      config,
      runtime,
      instructions: "test",
      onWarning: () => undefined,
      trace: sink,
    });
    expect(records).toHaveLength(1);
    expect(records[0]!.request).toBeDefined();
    expect(records[0]!.response).toBeDefined();
  });

  it("merges incremental transcript context and keeps it when the model call fails", async () => {
    const config = defaultConfig();
    config.llm.enabled = true;
    config.llm.traceDetail = "full";
    const { sink, records } = collectingSink();
    const runtime: ValidatorRuntime = {
      async validateBatch(_request, _instructions, _repair, _tools, onTranscript) {
        onTranscript?.({
          instructions: "custom system prompt",
          tools: [
            { name: "read_file", description: "Read context", parameters: { type: "object" } },
          ],
        });
        onTranscript?.({ history: [{ role: "user", content: "batch input" }] });
        throw new Error("provider unavailable");
      },
    };
    await runValidation({
      clusters: [cluster],
      occurrences: [occurrence],
      config,
      runtime,
      instructions: "custom system prompt",
      onWarning: () => undefined,
      trace: sink,
    });
    expect(records).toHaveLength(1);
    expect(records[0]!.error).toBe("provider unavailable");
    expect(records[0]!.transcript?.instructions).toBe("custom system prompt");
    expect(records[0]!.transcript?.tools?.[0]?.name).toBe("read_file");
    expect(records[0]!.transcript?.history).toEqual([{ role: "user", content: "batch input" }]);
  });
});

describe("rendered trace", () => {
  const attempt = (over: Partial<TraceRecord> = {}): TraceRecord => ({
    ts: "2026-01-01T00:00:00.000Z",
    event: "batch-attempt",
    batchId: "B-0001",
    attempt: 0,
    repair: false,
    clusterIds: ["C-000001"],
    durationMs: 12,
    accepted: true,
    ...over,
  });

  it("surfaces reasoning even though the provider puts it in rawContent", () => {
    const html = renderTraceHtml(
      [
        attempt({
          transcript: {
            history: [
              {
                type: "reasoning",
                content: [],
                rawContent: [{ type: "reasoning_text", text: "weighing entropy" }],
              },
              {
                type: "message",
                role: "assistant",
                content: [{ type: "output_text", text: '{"verdicts":[]}' }],
              },
            ],
          },
        }),
      ],
      { model: "reasoning-model", detail: "full" },
    );
    expect(html).toContain("Model reasoning");
    expect(html).toContain("weighing entropy");
    expect(html).toContain("Assistant messages");
  });

  it("shows tool calls including refusals", () => {
    const html = renderTraceHtml(
      [
        attempt(),
        attempt({
          event: "tool-call",
          accepted: false,
          tool: {
            name: "read_file",
            path: "other.ts",
            startLine: 1,
            endLine: 5,
            ok: false,
            error: "not readable",
          },
        }),
      ],
      { model: "m", detail: "full" },
    );
    expect(html).toContain("read_file");
    expect(html).toContain("refused");
    expect(html).toContain("not readable");
  });

  it("orders model configuration before conversation and payload details", () => {
    const html = renderTraceHtml(
      [
        attempt({
          request: { batchId: "B-0001" },
          response: { verdicts: [] },
          transcript: {
            instructions: "custom system prompt",
            tools: [
              { name: "read_file", description: "Read context", parameters: { type: "object" } },
            ],
            history: [
              { role: "user", content: "classify this" },
              { role: "assistant", content: "classified" },
            ],
          },
        }),
      ],
      { model: "m", detail: "full" },
    );
    expect(html).toContain("custom system prompt");
    expect(html).toContain("Available tools");
    expect(html.indexOf("Model configuration")).toBeLessThan(html.indexOf("Conversation"));
    expect(html.indexOf("Conversation")).toBeLessThan(html.indexOf("Payloads and results"));
  });

  it("says so when nothing was captured at metadata detail", () => {
    const html = renderTraceHtml([attempt()], { model: "m", detail: "metadata" });
    expect(html).toContain("No conversation captured");
  });

  it("escapes content and writes 0600 next to the jsonl", () => {
    const dir = tempDir("clearance-tracehtml-");
    const jsonl = path.join(dir, "t.jsonl");
    const dest = writeTraceHtml(
      jsonl,
      [
        attempt({
          transcript: {
            history: [{ type: "reasoning", rawContent: [{ text: "<img src=x onerror=1>" }] }],
          },
        }),
      ],
      { model: "m", detail: "full" },
    );
    expect(dest).toBe(path.join(dir, "t.html"));
    const html = fs.readFileSync(dest!, "utf8");
    expect(html).toContain("&lt;img src=x");
    expect(html).not.toContain("<img src=x");
    expect(fs.statSync(dest!).mode & 0o777).toBe(0o600);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
