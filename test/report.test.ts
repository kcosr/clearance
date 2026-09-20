import { describe, expect, it } from "vitest";
import { renderHtml } from "../src/report/html.js";
import { renderMarkdown } from "../src/report/markdown.js";
import { publicManifest } from "../src/report/public.js";
import { formatHumanSummary } from "../src/report/write.js";
import type { ScanResult } from "../src/types.js";
import { PEM_HEADER, SLACK_TOKEN } from "./helpers.js";

const result: ScanResult = {
  schemaVersion: "clearance.report/v1",
  outcome: "denied",
  exitCode: 2,
  failOn: "high",
  startedAt: "2024-01-01T00:00:00.000Z",
  finishedAt: "2024-01-01T00:00:01.000Z",
  roots: [{ rootId: "root-1", supplied: "/tmp/app", realPath: "/tmp/app", git: { kind: "none" } }],
  detectors: [{ name: "gitleaks", enabled: true, status: "completed", version: "8.30.1" }],
  occurrences: [
    {
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
      candidate: SLACK_TOKEN,
      candidateFingerprint: "abc",
    },
  ],
  clusters: [
    {
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
    },
    {
      clusterId: "C-000002",
      secretId: "H:def",
      presence: "current",
      rootId: "root-1",
      path: "id_rsa",
      lineStart: 1,
      lineEnd: 1,
      category: "private-key",
      severity: "critical",
      foundBy: ["native"],
      notFoundBy: [],
      occurrenceIds: ["o2"],
      locations: [{ path: "id_rsa", lineStart: 1, scanners: ["native"] }],
      effectiveStatus: "suppressed",
      effectiveSeverity: "critical",
      suppressionReason: "allowlisted",
    },
  ],
  coverage: [],
  skipped: [],
  walk: {
    walked: 2,
    scannable: 2,
    skippedHarmless: 0,
    excludedByConfig: 0,
    archive: 0,
    oversize: 0,
    unreadable: 0,
  },
  errors: [],
  artifacts: { manifest: "/tmp/m", markdown: "/tmp/md", html: "/tmp/h" },
};

describe("report", () => {
  it("omits raw secrets and PEM bodies from public artifacts", () => {
    const md = renderMarkdown(result, { showSuppressed: false, showHistoryCommits: false });
    const html = renderHtml(result, { showSuppressed: false, showHistoryCommits: false });
    const manifest = JSON.stringify(publicManifest(result));
    for (const text of [md, html, manifest]) {
      expect(text).not.toContain(SLACK_TOKEN);
      expect(text).not.toContain("xoxb-");
      expect(text).not.toContain(PEM_HEADER);
    }
    expect(md).toContain("1 findings suppressed");
    expect(md).not.toContain("id_rsa");
    expect(JSON.parse(manifest).occurrences[0].candidate).toBeUndefined();
  });

  it("html-escapes interpolated fields", () => {
    const tricky: ScanResult = {
      ...result,
      clusters: [
        {
          ...result.clusters[0]!,
          path: 'app<script>.env',
        },
      ],
    };
    const html = renderHtml(tricky, { showSuppressed: true, showHistoryCommits: false });
    expect(html).toContain("app&lt;script&gt;.env");
    expect(html).not.toContain("<script>");
  });

  it("leads with an actionable decision and explicit report paths", () => {
    const summary = formatHumanSummary(result);
    expect(summary).toContain("CLEARANCE RESULT: NOT CLEARED");
    expect(summary).toContain("Potential secrets were found at or above the configured severity threshold.");
    expect(summary).toContain("Open findings: 1");
    expect(summary).toContain("Highest severity: high");
    expect(summary).toContain("Markdown report: /tmp/md");
    expect(summary).toContain("HTML report: /tmp/h");
    expect(summary).not.toContain("AI tool");
  });
});
