import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { runOn, tempDir } from "../helpers.js";
import { makeClean, makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E11-two-roots", async () => {
  const parent = tempDir("clearance-e11-");
  trees.push(parent);
  const a = `${parent}/a`;
  const b = `${parent}/b`;
  fs.mkdirSync(a);
  fs.mkdirSync(b);
  makeClean(a);
  makeCurrentSecret(b);
  const { result, stdout, stderr } = await runOn([a, b], [], { cwd: parent });
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.clusters).toHaveLength(1);
  expect(result.clusters[0]?.rootId).toBe("root-2");
  expect(result.clusters[0]?.path).toBe("app.env");
});
