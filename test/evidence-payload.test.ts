import { describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { buildBatchCluster } from "../src/llm/validate.js";
import { publicCluster } from "../src/report/public.js";
import { renderMarkdown } from "../src/report/markdown.js";
import { renderHtml } from "../src/report/html.js";
import type { Cluster, DetectorResult, Occurrence, ScanResult } from "../src/types.js";

const LINE = 'const uri = "mongodb://svcuser:Tr0ub4dor3@db.internal:27017/app";';

function occurrence(overrides: Partial<Occurrence> = {}): Occurrence {
  return {
    occurrenceId: "o1",
    scanner: "trufflehog",
    rootId: "root-1",
    path: "test.cpp",
    lineStart: 1,
    lineEnd: 1,
    ruleId: "MongoDB",
    category: "secret",
    severity: "high",
    source: { kind: "workingTree" },
    extraction: "inexact",
    evidenceText: LINE,
    matchLine: LINE,
    ...overrides,
  };
}

function cluster(overrides: Partial<Cluster> = {}): Cluster {
  return {
    clusterId: "C-000001",
    secretId: "S:1",
    presence: "current",
    rootId: "root-1",
    path: "test.cpp",
    lineStart: 1,
    lineEnd: 1,
    category: "secret",
    severity: "high",
    description: "MongoDB credentials can be used to access the database.",
    foundBy: ["trufflehog"],
    notFoundBy: [],
    occurrenceIds: ["o1"],
    locations: [{ path: "test.cpp", lineStart: 1, scanners: ["trufflehog"] }],
    match: LINE,
    evidence: "inexact",
    effectiveStatus: "open",
    effectiveSeverity: "high",
    ...overrides,
  };
}

function scanResult(clusters: Cluster[], detectors: DetectorResult[]): ScanResult {
  return {
    schemaVersion: "clearance.report/v1",
    outcome: "denied",
    exitCode: 2,
    failOn: "high",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    roots: [{ rootId: "root-1", supplied: "/x", realPath: "/x", git: { kind: "none" } }],
    detectors,
    occurrences: [occurrence()],
    clusters,
    coverage: [],
    skipped: [],
    walk: { walked: 1, scannable: 1, skippedHarmless: 0, excludedByConfig: 0, archive: 0, oversize: 0, unreadable: 0 },
    errors: [],
    artifacts: { manifest: "", markdown: "", html: "" },
  };
}

const NO_HISTORY: DetectorResult[] = [
  { name: "gitleaks", enabled: true, status: "completed" },
  { name: "gitleaks-history", enabled: false, status: "skipped" },
  { name: "trufflehog", enabled: true, status: "completed" },
  { name: "trufflehog-history", enabled: false, status: "skipped" },
];

const WITH_HISTORY: DetectorResult[] = NO_HISTORY.map((d) =>
  d.name.endsWith("-history") ? { ...d, enabled: true, status: "completed" as const } : d,
);

describe("llm payload", () => {
  it("sends the matched line even when extraction is inexact", () => {
    const config = defaultConfig();
    const payload = buildBatchCluster(cluster(), [occurrence()], config);
    expect(payload.evidence.line).toBe(LINE);
    expect(payload.evidence.text).toContain("mongodb://");
  });

  it("carries the rule description and no host-internal fingerprint", () => {
    const payload = buildBatchCluster(cluster(), [occurrence()], defaultConfig());
    expect(payload.description).toContain("MongoDB");
    expect(JSON.stringify(payload)).not.toContain("fingerprint");
  });

  it("sends the value verbatim so the model can judge whether it is real", () => {
    // A redaction marker is indistinguishable from a live key once substituted,
    // which is why the redacted mode was removed rather than repaired.
    const occ = occurrence({ extraction: "exact", candidate: "Tr0ub4dor3", candidateFingerprint: "abcdef123456" });
    const payload = buildBatchCluster(
      cluster({ candidateFingerprint: "abcdef123456", evidence: "exact" }),
      [occ],
      defaultConfig(),
    );
    expect(payload.evidence.line).toContain("Tr0ub4dor3");
    expect(payload.evidence.candidate).toBe("Tr0ub4dor3");
    expect(payload.evidence.line).not.toContain("<SECRET:");
  });

  it("always sends content when the stage runs", () => {
    // There is no metadata-only mode: withholding content produced verdicts
    // that only restated the detector's claim, so enabling the stage is the
    // decision to send the line.
    const payload = buildBatchCluster(cluster(), [occurrence()], defaultConfig());
    expect(payload.evidence.line).toBe(LINE);
    expect(payload.evidence.text).toBeDefined();
    expect(payload.evidence).not.toHaveProperty("mode");
  });
});

describe("match line publication", () => {
  it("is withheld by default and published under includeRaw", () => {
    expect(publicCluster(cluster(), false).match).toBeUndefined();
    expect(publicCluster(cluster(), true).match).toBe(LINE);
  });

  it("is published even when extraction was inexact, unlike raw", () => {
    const published = publicCluster(cluster(), true);
    expect(published.match).toBe(LINE);
    expect(published.raw).toBeUndefined();
  });
});

describe("history rendering", () => {
  const opts = { showSuppressed: false, showHistoryCommits: false };

  it("omits the historical section and column when no history detector is enabled", () => {
    const result = scanResult([cluster()], NO_HISTORY);
    const md = renderMarkdown(result, opts);
    const html = renderHtml(result, opts);
    expect(md).not.toContain("Historical (not in working tree)");
    expect(md).not.toContain("| History |");
    expect(html).not.toContain("Historical (not in working tree)");
    expect(html).not.toContain("<th>History</th>");
  });

  it("keeps them when a history detector is enabled", () => {
    const result = scanResult([cluster()], WITH_HISTORY);
    expect(renderMarkdown(result, opts)).toContain("Historical (not in working tree)");
    expect(renderHtml(result, opts)).toContain("<th>History</th>");
  });

  it("keeps them when historical clusters exist regardless of detector state", () => {
    const historical = cluster({ clusterId: "C-000002", presence: "historical" });
    const result = scanResult([historical], NO_HISTORY);
    expect(renderMarkdown(result, opts)).toContain("Historical (not in working tree)");
  });
});
describe("suppressed rendering", () => {
  const suppressedCluster = cluster({
    clusterId: "C-000009",
    effectiveStatus: "suppressed",
    suppressionReason: "allowlisted",
  });

  it("keeps suppressed clusters out of the findings tables", () => {
    const result = scanResult([cluster(), suppressedCluster], NO_HISTORY);
    const md = renderMarkdown(result, { showSuppressed: true, showHistoryCommits: false });
    const currentSection = md.slice(md.indexOf("## Current"), md.indexOf("## Suppressed"));
    expect(currentSection).toContain("C-000001");
    expect(currentSection).not.toContain("C-000009");
  });

  it("gives them their own section with a reason column", () => {
    const result = scanResult([cluster(), suppressedCluster], NO_HISTORY);
    const md = renderMarkdown(result, { showSuppressed: true, showHistoryCommits: false });
    const html = renderHtml(result, { showSuppressed: true, showHistoryCommits: false });
    expect(md).toContain("## Suppressed");
    expect(md.slice(md.indexOf("## Suppressed"))).toContain("allowlisted");
    expect(html).toContain("<h2>Suppressed</h2>");
    expect(html).toContain("<th>Reason</th>");
  });

  it("omits the section entirely without --show-suppressed", () => {
    const result = scanResult([cluster(), suppressedCluster], NO_HISTORY);
    const md = renderMarkdown(result, { showSuppressed: false, showHistoryCommits: false });
    const html = renderHtml(result, { showSuppressed: false, showHistoryCommits: false });
    expect(md).not.toContain("## Suppressed");
    expect(md).not.toContain("C-000009");
    expect(html).not.toContain("<h2>Suppressed</h2>");
    expect(md).toContain("1 findings suppressed");
  });

  it("attributes an applied LLM false_positive rather than an allowlist", () => {
    const byLlm = cluster({
      clusterId: "C-000010",
      effectiveStatus: "suppressed",
      llm: { status: "false_positive", confidence: 0.9 },
    });
    const result = scanResult([byLlm], NO_HISTORY);
    const md = renderMarkdown(result, { showSuppressed: true, showHistoryCommits: false });
    expect(md.slice(md.indexOf("## Suppressed"))).toContain("llm false_positive");
  });
});
