import { describe, expect, it } from "vitest";
import { decideOutcome } from "../src/outcome.js";
import type { Cluster, DetectorResult } from "../src/types.js";

const openHigh: Cluster = {
  clusterId: "C-000001",
  secretId: "s",
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
  locations: [],
  effectiveStatus: "open",
  effectiveSeverity: "high",
};

const detectors: DetectorResult[] = [{ name: "native", enabled: true, status: "completed" }];

describe("outcome", () => {
  it("returns clean when there are no findings or coverage holes", () => {
    expect(decideOutcome({ clusters: [], coverage: [], detectors, errors: [], failOn: "high" }).outcome).toBe(
      "clean",
    );
  });

  it("returns denied for unsuppressed failOn findings", () => {
    expect(
      decideOutcome({ clusters: [openHigh], coverage: [], detectors, errors: [], failOn: "high" }).exitCode,
    ).toBe(2);
  });

  it("returns findings when leftovers are below failOn", () => {
    const low = { ...openHigh, effectiveSeverity: "low" as const, severity: "low" as const };
    expect(decideOutcome({ clusters: [low], coverage: [], detectors, errors: [], failOn: "high" }).outcome).toBe(
      "findings",
    );
  });

  it("returns incomplete for coverage holes without denied secrets", () => {
    expect(
      decideOutcome({
        clusters: [],
        coverage: [{ rootId: "root-1", path: "a.zip", reason: "archive" }],
        detectors,
        errors: [],
        failOn: "high",
      }).outcome,
    ).toBe("incomplete");
  });

  it("prefers denied over incomplete", () => {
    expect(
      decideOutcome({
        clusters: [openHigh],
        coverage: [{ rootId: "root-1", path: "a.zip", reason: "archive" }],
        detectors,
        errors: [],
        failOn: "high",
      }).outcome,
    ).toBe("denied");
  });

  it("prefers error over denied", () => {
    expect(
      decideOutcome({
        clusters: [openHigh],
        coverage: [],
        detectors: [{ name: "gitleaks", enabled: true, status: "failed", error: "missing-binary" }],
        errors: [],
        failOn: "high",
      }).outcome,
    ).toBe("error");
  });
});
