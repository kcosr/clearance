import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { createConstantRuntime } from "../../src/llm/runtime.js";
import { runOn, tempDir } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E14-llm-scripted-confirm", async () => {
  const root = tempDir("clearance-e14-");
  trees.push(root);
  makeCurrentSecret(root);
  const { result, stdout, stderr } = await runOn(root, ["--llm"], {
    llmRuntime: createConstantRuntime("confirmed"),
  });
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.clusters[0]?.llm?.status).toBe("confirmed");
});
