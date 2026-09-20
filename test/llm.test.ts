import { describe, expect, it } from "vitest";
import { applyVerdicts, partitionBatches } from "../src/llm/validate.js";
import { validateBatchResponse as schemaValidate } from "../src/llm/schema.js";
import { createScriptedRuntime, type RepairContext, type ValidatorRuntime } from "../src/llm/runtime.js";
import { runValidation } from "../src/llm/validate.js";
import { defaultConfig } from "../src/config.js";
import type { Cluster, Occurrence } from "../src/types.js";

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
  ruleId: "slack",
  category: "slack-token",
  severity: "high",
  source: { kind: "workingTree" },
  extraction: "exact",
  candidate: "xoxb-not-for-reports",
};

describe("llm", () => {
  it("rejects unknown cluster IDs", () => {
    const request = { batchId: "B-0001", clusters: [] as never[] };
    const checked = schemaValidate(
      { batchId: "B-0001", verdicts: [{ clusterId: "nope", status: "confirmed", confidence: 1, rationale: "x" }] },
      { batchId: "B-0001", clusters: [{ clusterId: "C-000001" }] as never },
      new Set(["C-000001"]),
    );
    expect(checked.ok).toBe(false);
    void request;
  });

  it("stores advisory verdicts when canOverride is false", () => {
    const next = applyVerdicts(
      [cluster],
      new Map([["C-000001", { status: "false_positive", confidence: 0.9, rationale: "docs" }]]),
      [occurrence],
      false,
    );
    expect(next[0]?.effectiveStatus).toBe("open");
    expect(next[0]?.llm?.advisory).toBe(true);
  });

  it("suppresses false positives when canOverride is true", () => {
    const next = applyVerdicts(
      [cluster],
      new Map([["C-000001", { status: "false_positive", confidence: 0.9, rationale: "docs" }]]),
      [occurrence],
      true,
    );
    expect(next[0]?.effectiveStatus).toBe("suppressed");
  });

  it("scrubs candidate substrings from rationale", () => {
    const next = applyVerdicts(
      [cluster],
      new Map([["C-000001", { status: "confirmed", confidence: 1, rationale: "saw xoxb-not-for-reports here" }]]),
      [occurrence],
      false,
    );
    expect(next[0]?.llm?.rationale).not.toContain("xoxb-");
    expect(next[0]?.llm?.rationale).toContain("[redacted]");
  });

  it("keeps completed batches and marks the rest unreviewed on timeout", async () => {
    const config = defaultConfig();
    config.llm.enabled = true;
    config.llm.timeoutMs = 30;
    config.llm.batch.maxClusters = 1;
    config.llm.batch.maxBytes = 10_000_000;
    config.llm.batch.maxTokens = 10_000_000;
    const second: Cluster = { ...cluster, clusterId: "C-000002", path: "other.env", occurrenceIds: ["o2"] };
    let calls = 0;
    const runtime = createScriptedRuntime(async (request) => {
      calls += 1;
      if (calls > 1) await new Promise((resolve) => setTimeout(resolve, 80));
      return {
        batchId: request.batchId,
        verdicts: request.clusters.map((item) => ({
          clusterId: item.clusterId,
          status: "confirmed" as const,
          confidence: 1,
          rationale: "ok",
        })),
      };
    });
    const result = await runValidation({
      clusters: [cluster, second],
      occurrences: [occurrence, { ...occurrence, occurrenceId: "o2", path: "other.env" }],
      config,
      runtime,
      instructions: "test",
      onWarning: () => undefined,
    });
    expect(result.status).toBe("partial");
    expect(result.clusters.some((item) => item.llm?.status === "unreviewed")).toBe(true);
  });

  it("partitions by maxClusters", () => {
    const config = defaultConfig();
    config.llm.batch.maxClusters = 1;
    config.llm.batch.maxBytes = 1_000_000;
    config.llm.batch.maxTokens = 1_000_000;
    const batches = partitionBatches(
      [
        { ...cluster, clusterId: "C-000001" } as never,
        { ...cluster, clusterId: "C-000002", path: "b.env" } as never,
      ],
      config,
    );
    expect(batches).toHaveLength(2);
  });
  it("feeds the rejected output and diagnostics into the repair attempt", async () => {
    // A repair that re-sends the identical request just gets the identical
    // rejected output back, so the diagnostics have to reach the model.
    const config = defaultConfig();
    config.llm.enabled = true;
    config.llm.maxRepairs = 1;
    const seen: Array<RepairContext | undefined> = [];
    let call = 0;
    const runtime: ValidatorRuntime = {
      async validateBatch(request, _instructions, repair) {
        seen.push(repair);
        call += 1;
        if (call === 1) {
          // Unknown clusterId: a guardrail failure, which is repairable.
          return { batchId: request.batchId, verdicts: [{ clusterId: "C-999999", status: "confirmed", confidence: 1, rationale: "wrong id" }] } as never;
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

    const result = await runValidation({
      clusters: [cluster],
      occurrences: [occurrence],
      config,
      runtime,
      instructions: "test",
      onWarning: () => undefined,
    });

    expect(call).toBe(2);
    expect(seen[0]).toBeUndefined();
    expect(seen[1]).toBeDefined();
    expect(seen[1]!.attempt).toBe(1);
    expect(seen[1]!.rejected).toContain("C-999999");
    expect(seen[1]!.diagnostics.join(" ")).toContain("C-999999");
    expect(result.clusters[0]?.llm?.status).toBe("confirmed");
  });
});
