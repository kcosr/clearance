import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { detector, runOn, tempDir } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E15-too-old-gitleaks", async () => {
  const root = tempDir("clearance-e15-");
  trees.push(root);
  makeCurrentSecret(root);
  const binDir = tempDir("clearance-old-gitleaks-");
  trees.push(binDir);
  const shim = path.join(binDir, "gitleaks");
  fs.writeFileSync(shim, "#!/bin/sh\necho 8.16.0\n");
  fs.chmodSync(shim, 0o755);
  const { result, stdout, stderr } = await runOn(root, ["--no-trufflehog"], {
    env: { ...process.env, PATH: `${binDir}:${process.env.PATH ?? ""}` },
  });
  assertScenario(result, stdout, stderr, { exit: 3, outcome: "error" });
  expect(detector(result, "gitleaks").status).toBe("failed");
  expect(detector(result, "gitleaks").error).toBe("unsupported-version");
});
