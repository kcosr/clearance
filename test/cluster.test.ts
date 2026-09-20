import { describe, expect, it } from "vitest";
import { clusterOccurrences } from "../src/cluster.js";
import { candidateFingerprint, newRunKey } from "../src/ids.js";
import type { DetectorResult, Occurrence } from "../src/types.js";

const detectors: DetectorResult[] = [
  { name: "native", enabled: true, status: "completed" },
  { name: "gitleaks", enabled: true, status: "completed" },
  { name: "trufflehog", enabled: true, status: "completed" },
  { name: "gitleaks-history", enabled: true, status: "completed" },
  { name: "trufflehog-history", enabled: true, status: "completed" },
];

function occ(partial: Partial<Occurrence> & Pick<Occurrence, "occurrenceId" | "scanner" | "path" | "source">): Occurrence {
  return {
    rootId: "root-1",
    lineStart: 1,
    lineEnd: 1,
    ruleId: "slack",
    category: "slack-token",
    severity: "high",
    extraction: "exact",
    ...partial,
  };
}

describe("cluster", () => {
  it("merges same-line working-tree hits from two scanners", () => {
    const key = newRunKey();
    const fp = candidateFingerprint(key, "token");
    const clusters = clusterOccurrences(
      [
        occ({
          occurrenceId: "o1",
          scanner: "gitleaks",
          path: "app.env",
          source: { kind: "workingTree" },
          candidateFingerprint: fp,
        }),
        occ({
          occurrenceId: "o2",
          scanner: "trufflehog",
          path: "app.env",
          source: { kind: "workingTree" },
          candidateFingerprint: fp,
        }),
      ],
      detectors,
    );
    expect(clusters).toHaveLength(1);
    expect(clusters[0]?.presence).toBe("current");
    expect(clusters[0]?.foundBy).toEqual(["gitleaks", "trufflehog"]);
    expect(clusters[0]?.notFoundBy).toEqual(["native"]);
  });

  it("joins one inexact hit to an unambiguous exact hit at the same location", () => {
    const fp = candidateFingerprint(newRunKey(), "complete candidate");
    const clusters = clusterOccurrences(
      [
        occ({
          occurrenceId: "o1",
          scanner: "gitleaks",
          path: "key.pem",
          lineStart: 1,
          lineEnd: 27,
          category: "private-key",
          extraction: "inexact",
          source: { kind: "workingTree" },
        }),
        occ({
          occurrenceId: "o2",
          scanner: "trufflehog",
          path: "key.pem",
          category: "private-key",
          candidateFingerprint: fp,
          source: { kind: "workingTree" },
        }),
      ],
      detectors,
    );

    expect(clusters).toHaveLength(1);
    expect(clusters[0]?.secretId).toBe(`H:${fp}`);
    expect(clusters[0]?.foundBy).toEqual(["gitleaks", "trufflehog"]);
    expect(clusters[0]?.evidence).toBe("inexact");
  });

  it("does not location-merge different categories or merely adjacent ranges", () => {
    const first = candidateFingerprint(newRunKey(), "first candidate");
    const second = candidateFingerprint(newRunKey(), "second candidate");
    const clusters = clusterOccurrences(
      [
        occ({
          occurrenceId: "o1",
          scanner: "gitleaks",
          path: "app.env",
          lineStart: 1,
          lineEnd: 1,
          category: "generic-password",
          extraction: "inexact",
          source: { kind: "workingTree" },
        }),
        occ({
          occurrenceId: "o2",
          scanner: "trufflehog",
          path: "app.env",
          lineStart: 1,
          lineEnd: 1,
          category: "private-key",
          candidateFingerprint: first,
          source: { kind: "workingTree" },
        }),
        occ({
          occurrenceId: "o3",
          scanner: "native",
          path: "app.env",
          lineStart: 2,
          lineEnd: 2,
          category: "generic-password",
          candidateFingerprint: second,
          source: { kind: "workingTree" },
        }),
      ],
      detectors,
    );

    expect(clusters).toHaveLength(3);
  });

  it("keeps an inexact hit separate when distinct exact candidates overlap it", () => {
    const first = candidateFingerprint(newRunKey(), "first");
    const second = candidateFingerprint(newRunKey(), "second");
    const clusters = clusterOccurrences(
      [
        occ({
          occurrenceId: "o1",
          scanner: "gitleaks",
          path: "bundle.txt",
          lineStart: 1,
          lineEnd: 10,
          extraction: "inexact",
          source: { kind: "workingTree" },
        }),
        occ({
          occurrenceId: "o2",
          scanner: "native",
          path: "bundle.txt",
          lineStart: 3,
          lineEnd: 3,
          candidateFingerprint: first,
          source: { kind: "workingTree" },
        }),
        occ({
          occurrenceId: "o3",
          scanner: "trufflehog",
          path: "bundle.txt",
          lineStart: 7,
          lineEnd: 7,
          candidateFingerprint: second,
          source: { kind: "workingTree" },
        }),
      ],
      detectors,
    );

    expect(clusters).toHaveLength(3);
  });

  it("keeps distant same-file hits as two current clusters sharing secretId", () => {
    const fp = candidateFingerprint(newRunKey(), "token");
    const clusters = clusterOccurrences(
      [
        occ({
          occurrenceId: "o1",
          scanner: "gitleaks",
          path: "app.env",
          lineStart: 5,
          lineEnd: 5,
          source: { kind: "workingTree" },
          candidateFingerprint: fp,
        }),
        occ({
          occurrenceId: "o2",
          scanner: "gitleaks",
          path: "app.env",
          lineStart: 30,
          lineEnd: 30,
          source: { kind: "workingTree" },
          candidateFingerprint: fp,
        }),
      ],
      detectors,
    );
    expect(clusters).toHaveLength(2);
    expect(clusters[0]?.secretId).toBe(clusters[1]?.secretId);
  });

  it("collapses history to one cluster and attaches it to working-tree hits", () => {
    const fp = candidateFingerprint(newRunKey(), "token");
    const clusters = clusterOccurrences(
      [
        occ({
          occurrenceId: "o1",
          scanner: "gitleaks",
          path: "app.env",
          source: { kind: "workingTree" },
          candidateFingerprint: fp,
        }),
        occ({
          occurrenceId: "o2",
          scanner: "gitleaks",
          path: "app.env",
          source: { kind: "git", commit: "aaa" },
          candidateFingerprint: fp,
        }),
        occ({
          occurrenceId: "o3",
          scanner: "gitleaks",
          path: "other.env",
          source: { kind: "git", commit: "bbb" },
          candidateFingerprint: fp,
        }),
      ],
      detectors,
    );
    expect(clusters).toHaveLength(1);
    expect(clusters[0]?.presence).toBe("current_and_historical");
    expect(clusters[0]?.locations.some((loc) => loc.path === "other.env")).toBe(true);
  });

  it("omits native from historical-only notFoundBy", () => {
    const fp = candidateFingerprint(newRunKey(), "token");
    const clusters = clusterOccurrences(
      [
        occ({
          occurrenceId: "o1",
          scanner: "gitleaks",
          path: "app.env",
          source: { kind: "git", commit: "aaa" },
          candidateFingerprint: fp,
        }),
      ],
      detectors,
    );
    expect(clusters[0]?.presence).toBe("historical");
    expect(clusters[0]?.notFoundBy).toEqual(["trufflehog"]);
  });
});
