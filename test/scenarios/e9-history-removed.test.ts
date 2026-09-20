import { afterEach, expect, it, vi } from "vitest";
import * as evidence from "../../src/evidence.js";
import fs from "node:fs";
import path from "node:path";
import { runOn, tempDir, SLACK_TOKEN } from "../helpers.js";
import { makeHistoryRemoved } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
  vi.restoreAllMocks();
});

it("E9-history-removed", async () => {
  const root = tempDir("clearance-e9-");
  trees.push(root);
  makeHistoryRemoved(root);
  expect(fs.existsSync(path.join(root, "app.env"))).toBe(false);
  const extraction = vi.spyOn(evidence, "extractEvidence");
  const { result, stdout, stderr } = await runOn(root, [
    "--gitleaks-history",
    "--trufflehog-history",
    "--progress",
  ]);
  expect(["denied", "findings"]).toContain(result.outcome);
  // Forced live output intentionally contains raw hits; reports and stdout do not.
  const otherStderr = stderr
    .split("\n")
    .filter(
      (line) => !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC finding \[unverified\] /.test(line),
    )
    .join("\n");
  assertScenario(result, stdout, otherStderr, { exit: result.exitCode, outcome: result.outcome });
  expect(extraction.mock.calls.filter(([occ]) => occ.source.kind === "git")).toHaveLength(
    result.occurrences.filter((occ) => occ.source.kind === "git").length,
  );
  const live = stderr.split("\n").filter((line) => line.includes("finding [unverified]"));
  expect(
    live.some(
      (line) => line.includes("gitleaks/") && line.includes("git=") && line.includes(SLACK_TOKEN),
    ),
  ).toBe(true);
  expect(
    live.some(
      (line) => line.includes("trufflehog/") && line.includes("git=") && line.includes(SLACK_TOKEN),
    ),
  ).toBe(true);
  const historical = result.clusters.filter((cluster) => cluster.presence === "historical");
  expect(historical).toHaveLength(1);
  const paths = new Set(historical[0]?.locations.map((loc) => loc.path));
  expect(paths.has("app.env")).toBe(true);
  expect(paths.has("other.env")).toBe(true);
});
