import { describe, expect, it } from "vitest";
import { clusterOccurrences } from "../src/cluster.js";
import { defaultConfig } from "../src/config.js";
import { applySuppressions } from "../src/suppress.js";
import type { DetectorResult, Occurrence } from "../src/types.js";
import { SLACK_TOKEN } from "./helpers.js";

const detectors: DetectorResult[] = [{ name: "gitleaks", enabled: true, status: "completed" }];

describe("suppress", () => {
  it("allowlists exact extracted candidates", () => {
    const occ: Occurrence = {
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
    };
    const clusters = clusterOccurrences([occ], detectors);
    const config = defaultConfig();
    config.suppress.strings = [SLACK_TOKEN];
    const next = applySuppressions([occ], clusters, config);
    expect(next.occurrences[0]?.suppressed).toBe(true);
    expect(next.clusters[0]?.effectiveStatus).toBe("suppressed");
  });

  it("does not suppress inexact extractions", () => {
    const occ: Occurrence = {
      occurrenceId: "o1",
      scanner: "trufflehog",
      rootId: "root-1",
      path: "app.env",
      lineStart: 1,
      lineEnd: 1,
      ruleId: "generic",
      category: "secret",
      severity: "high",
      source: { kind: "workingTree" },
      extraction: "inexact",
      candidate: SLACK_TOKEN,
    };
    const clusters = clusterOccurrences([occ], detectors);
    const config = defaultConfig();
    config.suppress.strings = [SLACK_TOKEN];
    const next = applySuppressions([occ], clusters, config);
    expect(next.clusters[0]?.effectiveStatus).toBe("open");
  });

  it("suppresses an inexact corroborating hit joined to an allowlisted exact candidate", () => {
    const exact: Occurrence = {
      occurrenceId: "o1",
      scanner: "trufflehog",
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
      candidateFingerprint: "same-candidate",
    };
    const inexact: Occurrence = {
      occurrenceId: "o2",
      scanner: "gitleaks",
      rootId: "root-1",
      path: "app.env",
      lineStart: 1,
      lineEnd: 1,
      ruleId: "slack",
      category: "slack-token",
      severity: "high",
      source: { kind: "workingTree" },
      extraction: "inexact",
    };
    const occurrences = [exact, inexact];
    const clusters = clusterOccurrences(occurrences, [
      { name: "gitleaks", enabled: true, status: "completed" },
      { name: "trufflehog", enabled: true, status: "completed" },
    ]);
    const config = defaultConfig();
    config.suppress.strings = [SLACK_TOKEN];
    const next = applySuppressions(occurrences, clusters, config);

    expect(clusters).toHaveLength(1);
    expect(next.occurrences.every((occ) => occ.suppressed)).toBe(true);
    expect(next.clusters[0]?.effectiveStatus).toBe("suppressed");
  });
});
