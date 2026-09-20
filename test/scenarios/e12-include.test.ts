import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { runOn, SLACK_LINE, tempDir, writeTree } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E12-include", async () => {
  const root = tempDir("clearance-e12-");
  trees.push(root);
  makeCurrentSecret(root);
  writeTree(root, { "tmp/token.env": SLACK_LINE });
  const { result, stdout, stderr } = await runOn(root, ["--include", "app.env"]);
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.clusters.every((cluster) => cluster.path === "app.env")).toBe(true);
  expect(result.occurrences.every((occ) => occ.path === "app.env")).toBe(true);
});
