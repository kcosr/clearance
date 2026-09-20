import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { runOn, tempDir, writeZip } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { SLACK_LINE } from "../helpers.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E7-zip-and-live", async () => {
  const root = tempDir("clearance-e7-");
  trees.push(root);
  makeCurrentSecret(root);
  writeZip(path.join(root, "vendor/pkg.zip"), { "nested.txt": SLACK_LINE });
  const { result, stdout, stderr } = await runOn(root);
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.coverage.some((item) => item.reason === "archive")).toBe(true);
});
