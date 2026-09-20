import { afterEach, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { detector, runOn, SLACK_LINE, tempDir, writeTree } from "./helpers.js";

const trees: string[] = [];
afterEach(() => {
  for (const tree of trees) fs.rmSync(tree, { recursive: true, force: true });
  trees.length = 0;
});

it("a secret inside an excluded directory does not fail the trufflehog adapter", async () => {
  // TruffleHog exits 183 because it matched, but every hit is dropped by our
  // include/exclude post-filter. Cross-checking the exit code against the
  // filtered count made this a run error on any repo with a secret in
  // node_modules/**, which is the default exclude.
  const root = tempDir("clearance-reg-excluded-");
  trees.push(root);
  writeTree(root, {
    "README.md": "# ok\n",
    "node_modules/pkg/app.env": SLACK_LINE,
  });

  const { result } = await runOn(root);
  expect(detector(result, "trufflehog").status).toBe("completed");
  expect(detector(result, "trufflehog").error).toBeUndefined();
  expect(result.outcome).toBe("clean");
  expect(result.exitCode).toBe(0);
  expect(result.clusters).toHaveLength(0);
});

it("a nested --include glob still descends into subdirectories", async () => {
  // Include globs describe files. Matching them against directory entries
  // pruned the subtree before its files were considered, so the walk saw
  // nothing while the scanner post-filter still matched on file paths.
  const root = tempDir("clearance-reg-include-");
  trees.push(root);
  writeTree(root, {
    "top.txt": "nothing\n",
    "nested/app.env": SLACK_LINE,
  });

  const { result } = await runOn(root, ["--include", "**/*.env"]);
  expect(result.walk.walked).toBe(1);
  expect(result.walk.scannable).toBe(1);
  expect(result.clusters).toHaveLength(1);
  expect(result.clusters[0]!.path).toBe("nested/app.env");
});

it("a deep --include path matches the file it names", async () => {
  const root = tempDir("clearance-reg-include2-");
  trees.push(root);
  writeTree(root, {
    "nested/deep/app.env": SLACK_LINE,
    "nested/deep/other.txt": "nothing\n",
  });

  const { result } = await runOn(root, ["--include", "nested/deep/app.env"]);
  expect(result.walk.scannable).toBe(1);
  expect(result.clusters.map((cluster) => cluster.path)).toEqual(["nested/deep/app.env"]);
});

it("refuses admin policy that lives inside a scan root", async () => {
  // A scanned repo must not be able to supply its own rules and clear itself.
  const root = tempDir("clearance-reg-policy-");
  const outside = tempDir("clearance-reg-policy-cfg-");
  trees.push(root, outside);
  writeTree(root, {
    "app.env": SLACK_LINE,
    "rules.d/evil.toml": 'schema_version = "clearance-rules/1"\n',
  });
  const configPath = path.join(outside, "config.toml");
  fs.writeFileSync(
    configPath,
    `[detectors.native]\nenabled = true\nrulesD = ${JSON.stringify(path.join(root, "rules.d"))}\n`,
  );

  const { result, stderr } = await runOn(root, ["--config", configPath]);
  expect(result.outcome).toBe("error");
  expect(result.exitCode).toBe(3);
  expect(stderr).toContain("admin policy inside a scan root");
});
