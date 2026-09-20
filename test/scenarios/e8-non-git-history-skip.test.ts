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

it("E8-non-git-history-skip", async () => {
  const root = tempDir("clearance-e8-");
  trees.push(root);
  makeCurrentSecret(root);
  const { result, stdout, stderr } = await runOn(root, ["--gitleaks-history", "--trufflehog-history"]);
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(detector(result, "gitleaks-history").status).toBe("skipped");
  expect(detector(result, "gitleaks-history").error).toBe("not-a-git-repository");
  expect(detector(result, "trufflehog-history").status).toBe("skipped");
});
