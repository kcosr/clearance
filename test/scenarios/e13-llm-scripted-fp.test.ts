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

it("E13-llm-scripted-fp", async () => {
  const root = tempDir("clearance-e13-");
  trees.push(root);
  makeCurrentSecret(root);
  const { result, stdout, stderr } = await runOn(root, ["--llm", "--llm-override"], {
    llmRuntime: createConstantRuntime("false_positive"),
  });
  assertScenario(result, stdout, stderr, { exit: 0, outcome: "clean" });
  expect(result.clusters[0]?.effectiveStatus).toBe("suppressed");
  expect(result.clusters[0]?.llm?.status).toBe("false_positive");
});

it("E13b-advisory", async () => {
  const root = tempDir("clearance-e13b-");
  trees.push(root);
  makeCurrentSecret(root);
  const { result, stdout, stderr } = await runOn(root, ["--llm", "--no-llm-override"], {
    llmRuntime: createConstantRuntime("false_positive"),
  });
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.clusters[0]?.effectiveStatus).toBe("open");
  expect(result.clusters[0]?.llm?.advisory).toBe(true);
});
