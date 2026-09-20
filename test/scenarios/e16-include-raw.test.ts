import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import { detector, readArtifacts, runOn, SLACK_TOKEN, tempDir } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("E16-include-raw publishes the exact candidate into the artifacts", async () => {
  const root = tempDir("clearance-e16-");
  trees.push(root);
  makeCurrentSecret(root);

  const { result, stdout, stderr } = await runOn(root, ["--include-raw"]);
  expect(result.exitCode).toBe(2);
  expect(result.outcome).toBe("denied");

  const artifacts = readArtifacts(result);
  const manifest = JSON.parse(artifacts.manifest) as {
    clusters: Array<{ raw?: string; evidence?: string }>;
  };
  const cluster = manifest.clusters[0];
  expect(cluster?.evidence).toBe("exact");
  expect(cluster?.raw).toBe(SLACK_TOKEN);

  // The inverse of the usual canary: the secret is expected in the artifacts...
  expect(artifacts.manifest).toContain(SLACK_TOKEN);
  expect(artifacts.markdown).toContain(SLACK_TOKEN);
  expect(artifacts.html).toContain(SLACK_TOKEN);
  // ...and still never on the console, so CI logs stay safe.
  expect(stdout).not.toContain(SLACK_TOKEN);
  expect(stderr).not.toContain(SLACK_TOKEN);

  // Raw output comes from the host's own extraction, so Gitleaks is still run
  // with --redact=100 and its redaction check still has to pass.
  expect(detector(result, "gitleaks").status).toBe("completed");

  // The human artifacts warn that they now carry credential material.
  expect(artifacts.markdown).toContain("This report may contain secrets");
  expect(artifacts.html).toContain("This report may contain secrets");
});

it("E16-include-raw publishes nothing extra without the flag", async () => {
  const root = tempDir("clearance-e16b-");
  trees.push(root);
  makeCurrentSecret(root);

  const { result, stdout, stderr } = await runOn(root);
  const artifacts = readArtifacts(result);
  const manifest = JSON.parse(artifacts.manifest) as { clusters: Array<{ raw?: string }> };
  expect(manifest.clusters.length).toBeGreaterThan(0);
  expect(manifest.clusters.every((cluster) => cluster.raw === undefined)).toBe(true);
  for (const text of [artifacts.manifest, artifacts.markdown, artifacts.html, stdout, stderr]) {
    expect(text).not.toContain(SLACK_TOKEN);
  }
});
