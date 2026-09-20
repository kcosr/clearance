import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { runOn, tempDir, writeTree } from "../helpers.js";
import { makeClean } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E5-png-clean", async () => {
  const root = tempDir("clearance-e5-");
  trees.push(root);
  makeClean(root);
  writeTree(root, { "logo.png": Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) });
  const { result, stdout, stderr } = await runOn(root);
  assertScenario(result, stdout, stderr, { exit: 0, outcome: "clean" });
  expect(result.skipped.some((item) => item.path === "logo.png" && item.reason === "harmless")).toBe(true);
});
