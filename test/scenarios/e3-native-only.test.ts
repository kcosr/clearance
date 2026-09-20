import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { PEM_HEADER, runOn, tempDir, writeTree } from "../helpers.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E3-native-only", async () => {
  const root = tempDir("clearance-e3-");
  trees.push(root);
  writeTree(root, { id_rsa: `${PEM_HEADER}\nAAAA\n-----END RSA PRIVATE KEY-----\n` });
  const { result, stdout, stderr } = await runOn(root, ["--no-gitleaks", "--no-trufflehog"]);
  assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });
  expect(result.occurrences.some((occ) => occ.scanner === "native" && occ.ruleId === "private-key")).toBe(true);
});
