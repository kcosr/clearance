import { describe, expect, it } from "vitest";
import { findingMessage, terminalQuote, verdictMessage } from "../src/live-findings.js";
import { buildBatchCluster, runValidation } from "../src/llm/validate.js";
import { defaultConfig } from "../src/config.js";
import type { Cluster, Occurrence } from "../src/types.js";

const occurrence: Occurrence = {
  occurrenceId: "o1",
  rootId: "root-1",
  path: "app.env",
  lineStart: 3,
  lineEnd: 3,
  scanner: "gitleaks",
  ruleId: "test-token",
  category: "credential",
  severity: "high",
  source: { kind: "workingTree" },
  extraction: "exact",
  candidate: "synthetic-token",
};
const cluster: Cluster = {
  clusterId: "C-1",
  secretId: "H:1",
  presence: "current",
  rootId: "root-1",
  path: "app.env",
  lineStart: 3,
  lineEnd: 3,
  category: "credential",
  severity: "high",
  foundBy: ["gitleaks"],
  notFoundBy: [],
  occurrenceIds: ["o1"],
  locations: [{ path: "app.env", lineStart: 3, scanners: ["gitleaks"] }],
  effectiveStatus: "open",
  effectiveSeverity: "high",
};

describe("live findings", () => {
  it("labels an in-flight batch timeout accurately", async () => {
    const config = defaultConfig();
    config.llm.timeoutMs = 20;
    const events: string[] = [];
    const result = await runValidation({
      clusters: [cluster],
      occurrences: [occurrence],
      config,
      instructions: "test",
      onWarning() {},
      onVerdict: (item, verdict) => events.push(verdictMessage(item, verdict, false)),
      runtime: { validateBatch: () => new Promise(() => {}) },
    });
    expect(events.join("\n")).toContain('unreviewed: "batch timeout"');
    expect(events.join("\n")).not.toContain("validation failed");
    expect(result.clusters[0]?.llm?.status).toBe("unreviewed");
  });
  it("quotes source text reversibly without terminal escapes, bidi controls, or forged lines", () => {
    const raw = 'multi\nline\r\t"\\\x1b[2J\x9b2J\u202e\u2028\u2066';
    expect(JSON.parse(terminalQuote(raw))).toBe(raw);
    const text = findingMessage({
      ...occurrence,
      path: raw,
      candidate: raw,
      ruleId: raw,
      source: { kind: "git", commit: raw },
    });
    expect(text).not.toMatch(/[\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]/);
    expect(text).toContain("git=");
    const batch = buildBatchCluster(
      { ...cluster, path: raw },
      [{ ...occurrence, candidate: raw }],
      defaultConfig(),
    );
    expect(verdictMessage(batch, { status: "false_positive", rationale: raw }, false)).not.toMatch(
      /[\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]/,
    );
    expect(verdictMessage(batch, { status: "false_positive" }, false)).toContain("[advisory]");
  });

  it("distinguishes filename matches, inexact source lines, and unavailable candidates", () => {
    expect(findingMessage({ ...occurrence, matchKind: "filename" })).toContain("filename match");
    expect(findingMessage({ ...occurrence, matchKind: "filename" })).not.toContain(
      "synthetic-token",
    );
    const { candidate: _, ...withoutCandidate } = occurrence;
    expect(
      findingMessage({ ...withoutCandidate, extraction: "inexact", matchLine: "password=maybe" }),
    ).toContain('source line="password=maybe" (exact candidate unavailable)');
    expect(findingMessage({ ...withoutCandidate, extraction: "unavailable" })).toContain(
      "candidate unavailable",
    );
  });

  it.each(["accept", "fallback", "fail"] as const)(
    "streams accepted batch verdicts before the next batch and reports %s policy",
    async (failurePolicy) => {
      const config = defaultConfig();
      config.llm.failurePolicy = failurePolicy;
      config.llm.canOverride = true;
      config.llm.batch.maxClusters = 1;
      const events: string[] = [];
      let calls = 0;
      const result = await runValidation({
        clusters: [cluster, { ...cluster, clusterId: "C-2", path: "z.env", occurrenceIds: ["o2"] }],
        occurrences: [occurrence],
        config,
        instructions: "test",
        onWarning() {},
        progress: (message) => events.push(message),
        onVerdict: (item, verdict) => events.push(verdictMessage(item, verdict, true)),
        runtime: {
          async validateBatch(request) {
            if (++calls === 2) {
              expect(events.some((event) => event.includes('false_positive: "fixture"'))).toBe(
                true,
              );
              throw new Error("PRIVATE PROVIDER DIAGNOSTIC");
            }
            return {
              batchId: request.batchId,
              verdicts: request.clusters.map((item) => ({
                clusterId: item.clusterId,
                status: "false_positive",
                confidence: 1,
                rationale: "fixture",
              })),
            };
          },
        },
      });
      expect(events.join("\n")).not.toContain("PRIVATE PROVIDER DIAGNOSTIC");
      expect(events.join("\n")).toContain('unreviewed: "validation failed"');
      if (failurePolicy === "accept") {
        expect(events.join("\n")).toContain("batch verdicts applied");
        expect(result.clusters[0]?.effectiveStatus).toBe("suppressed");
      } else {
        expect(events.join("\n")).toContain("batch verdicts discarded by failure policy");
        expect(result.clusters[0]?.effectiveStatus).toBe("open");
      }
    },
  );
});
