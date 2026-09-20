import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { runOn, tempDir } from "../helpers.js";
import { makeZipOnly } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E6-zip-incomplete", async () => {
  const root = tempDir("clearance-e6-");
  trees.push(root);
  makeZipOnly(root);
  const { result, stdout, stderr } = await runOn(root);
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "incomplete" });
  expect(result.coverage.some((item) => item.reason === "archive")).toBe(true);
  expect(result.clusters.filter((cluster) => cluster.foundBy.includes("gitleaks"))).toHaveLength(0);
});
