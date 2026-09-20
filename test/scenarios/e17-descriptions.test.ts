import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { runOn, tempDir } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";
import { assertScenario } from "./assert.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E17-descriptions carries scanner rule text into clusters and reports", async () => {
  const root = tempDir("clearance-e17-");
  trees.push(root);
  makeCurrentSecret(root);

  const { result, stdout, stderr } = await runOn(root);
  const artifacts = assertScenario(result, stdout, stderr, { exit: 2, outcome: "denied" });

  const cluster = result.clusters[0]!;
  expect(cluster.description).toBeTruthy();
  expect(cluster.description!.toLowerCase()).toContain("slack");

  // Each scanner keeps its own text on its own occurrence.
  const gitleaksOcc = result.occurrences.find((occ) => occ.scanner === "gitleaks");
  const trufflehogOcc = result.occurrences.find((occ) => occ.scanner === "trufflehog");
  expect(gitleaksOcc?.message).toBeTruthy();
  expect(trufflehogOcc?.message).toBeTruthy();
  expect(gitleaksOcc?.message).not.toBe(trufflehogOcc?.message);

  // The description reaches both human reports, not just the manifest.
  expect(artifacts.markdown.toLowerCase()).toContain("slack");
  expect(artifacts.html.toLowerCase()).toContain("slack");

  // Only the fixed per-rule text is carried; detector-defined blobs are not.
  for (const text of [artifacts.manifest, artifacts.markdown, artifacts.html]) {
    expect(text).not.toContain("rotation_guide");
    expect(text).not.toContain("ExtraData");
    expect(text).not.toContain("SecretParts");
  }
});

it("E17-descriptions bounds scanner-supplied text", async () => {
  const root = tempDir("clearance-e17b-");
  trees.push(root);
  makeCurrentSecret(root);
  const { result } = await runOn(root);
  for (const cluster of result.clusters) {
    expect((cluster.description ?? "").length).toBeLessThanOrEqual(300);
  }
});
