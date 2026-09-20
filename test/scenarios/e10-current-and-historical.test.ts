import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { git, runOn, SLACK_LINE, tempDir, writeTree } from "../helpers.js";
import { makeHistoryRemoved } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E10-current-and-historical", async () => {
  const root = tempDir("clearance-e10-");
  trees.push(root);
  makeHistoryRemoved(root);
  writeTree(root, { "app.env": SLACK_LINE });
  git(root, ["add", "app.env"]);
  git(root, ["commit", "-m", "restore"], {
    GIT_AUTHOR_DATE: "2024-01-05T00:00:00 +0000",
    GIT_COMMITTER_DATE: "2024-01-05T00:00:00 +0000",
  });
  const { result, stdout, stderr } = await runOn(root, ["--gitleaks-history", "--trufflehog-history"]);
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.clusters.some((cluster) => cluster.presence === "current_and_historical")).toBe(true);
});
