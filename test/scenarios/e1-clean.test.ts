import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { runOn, tempDir } from "../helpers.js";
import { makeClean } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E1-clean", async () => {
  const root = tempDir("clearance-e1-");
  trees.push(root);
  makeClean(root);
  const { result, stdout, stderr } = await runOn(root);
  assertScenario(result, stdout, stderr, { exit: 0, outcome: "clean" });
  expect(result.clusters).toHaveLength(0);
});
