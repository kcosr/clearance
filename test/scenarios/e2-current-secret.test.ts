import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { detector, runOn, tempDir } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E2-current-secret", async () => {
  const root = tempDir("clearance-e2-");
  trees.push(root);
  makeCurrentSecret(root);
  const { result, stdout, stderr } = await runOn(root);
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.clusters).toHaveLength(1);
  expect(result.clusters[0]?.presence).toBe("current");
  expect(result.clusters[0]?.foundBy).toEqual(expect.arrayContaining(["gitleaks", "trufflehog"]));
  expect(detector(result, "gitleaks").status).toBe("completed");
  expect(detector(result, "trufflehog").status).toBe("completed");
});
