import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { runOn, SLACK_TOKEN, tempDir } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E4-suppress", async () => {
  const root = tempDir("clearance-e4-");
  trees.push(root);
  makeCurrentSecret(root);
  const { result, stdout, stderr } = await runOn(root, ["--suppress-string", SLACK_TOKEN]);
  const artifacts = assertScenario(result, stdout, stderr, { exit: 0, outcome: "clean" });
  expect(result.clusters[0]?.effectiveStatus).toBe("suppressed");
  expect(artifacts.markdown).toMatch(/findings suppressed/);
  expect(JSON.parse(artifacts.manifest).clusters).toHaveLength(1);
});
