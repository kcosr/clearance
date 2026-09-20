import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseArgs } from "../src/cli-parse.js";
import { applyCli, defaultConfig } from "../src/config.js";
import { applyTestFixturePolicy, isTestFixturePath } from "../src/test-fixtures.js";
import { clusterOccurrences } from "../src/cluster.js";
import { decideOutcome } from "../src/outcome.js";
import { renderMarkdown } from "../src/report/markdown.js";
import { renderHtml } from "../src/report/html.js";
import { publicManifest } from "../src/report/public.js";
import { git, initRepo, runOn, STRIPE_LIVE, tempDir, writeTree } from "./helpers.js";
import type { Occurrence, ScanResult } from "../src/types.js";

const dirs: string[] = [];
function tree(files: Record<string, string>): string {
  const dir = tempDir("clearance-fixture-policy-");
  dirs.push(dir);
  writeTree(dir, files);
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});
function occurrence(file: string, severity: Occurrence["severity"] = "high"): Occurrence {
  return {
    occurrenceId: file,
    rootId: "root-1",
    path: file,
    scanner: "native",
    lineStart: 1,
    lineEnd: 1,
    ruleId: "secret",
    category: "secret",
    severity,
    source: { kind: "workingTree" },
    extraction: "exact",
    candidate: "secret",
    candidateFingerprint: "same-secret",
  };
}
function policy(occurrences: Occurrence[], enabled: boolean) {
  const config = defaultConfig();
  config.scan.excludeTestFixtures = enabled;
  return applyTestFixturePolicy(occurrences, clusterOccurrences(occurrences, []), config);
}
function outcome(clusters: ScanResult["clusters"]) {
  return decideOutcome({ clusters, coverage: [], detectors: [], errors: [], failOn: "high" })
    .outcome;
}

describe("test fixture path context and policy", () => {
  it("is off by default and CLI overrides config in either direction", () => {
    const config = defaultConfig();
    expect(config.scan.excludeTestFixtures).toBe(false);
    const enabled = applyCli(config, parseArgs(["--exclude-test-fixtures"]));
    expect(enabled.scan.excludeTestFixtures).toBe(true);
    expect(
      applyCli(enabled, parseArgs(["--no-exclude-test-fixtures"])).scan.excludeTestFixtures,
    ).toBe(false);
    expect(() => parseArgs(["--skip-test-fixtures"])).toThrow();
  });
  it.each([
    "test/a.ts",
    "src/tests/a.ts",
    "__tests__/a.js",
    "fixtures/a.json",
    "__fixtures__/a.json",
    "AUTH.TEST.TS",
    "a.spec.ts",
    "a_fixture.json",
    "test_auth.py",
    "auth_test.go",
    "fixture_data.json",
    "spec_auth.rb",
    "auth.spec.integration.ts",
    "data.fixture.yaml",
  ])("labels %s", (file) => expect(isTestFixturePath(file)).toBe(true));
  it.each([
    "contest.ts",
    "latest.json",
    "specs/http.md",
    "testimony.txt",
    "fixtures-prod/a.ts",
    "src/tester.ts",
    "src/mytest.ts",
    "src/application.ts",
    "api/spec.yaml",
    "deploy/test.yaml",
    "config/test.env",
    "config/fixture.json",
    "application-test.properties",
    ".env.test",
    "values-test.yaml",
    "appsettings.Test.json",
    "openapi-spec.yaml",
    "api.spec.json",
    "pod-spec.yaml",
    "package.spec",
    "test_config.json",
    "spec_config.yaml",
  ])("does not label %s", (file) => expect(isTestFixturePath(file)).toBe(false));
  it("labels test findings by default without changing their verdict or blocking outcome", () => {
    const result = policy([occurrence("tests/a.ts")], false);
    expect(result.occurrences[0]?.pathContext).toBe("test-fixture");
    expect(result.occurrences[0]?.policyExclusion).toBeUndefined();
    expect(result.clusters[0]?.pathContext).toBe("test-fixture");
    expect(result.clusters[0]?.effectiveStatus).toBe("open");
    expect(result.clusters[0]?.llm).toBeUndefined();
    expect(outcome(result.clusters)).toBe("denied");
  });
  it("excludes only test locations and preserves applied LLM judgments", () => {
    const config = defaultConfig();
    config.scan.excludeTestFixtures = true;
    const occurrences = [occurrence("tests/a.ts")];
    const clusters = clusterOccurrences(occurrences, []);
    clusters[0]!.llm = { status: "confirmed", rationale: "Looks like a credential." };
    const result = applyTestFixturePolicy(occurrences, clusters, config);
    expect(result.clusters[0]).toMatchObject({
      effectiveStatus: "policy_excluded",
      policyExclusion: "test-fixture",
      llm: { status: "confirmed" },
    });
    expect(result.occurrences[0]?.policyExclusion).toBe("test-fixture");
    expect(outcome(result.clusters)).toBe("clean");
    expect(
      decideOutcome({
        clusters: result.clusters,
        coverage: [{ rootId: "root-1", path: "tests/a.ts", reason: "classifier-incomplete" }],
        detectors: [],
        errors: [],
        failOn: "high",
      }).outcome,
    ).toBe("incomplete");
  });
  it.each(["allowlisted", "llm false_positive"])(
    "preserves %s suppression and shows its fixture policy annotation exactly once",
    (reason) => {
      const config = defaultConfig();
      config.scan.excludeTestFixtures = true;
      const occurrences = [occurrence("tests/a.ts")];
      const clusters = clusterOccurrences(occurrences, []);
      clusters[0]!.effectiveStatus = "suppressed";
      if (reason === "allowlisted") clusters[0]!.suppressionReason = "allowlisted";
      else clusters[0]!.llm = { status: "false_positive", rationale: "Synthetic fixture." };
      const annotated = applyTestFixturePolicy(occurrences, clusters, config);
      expect(annotated.clusters[0]).toMatchObject({
        effectiveStatus: "suppressed",
        policyExclusion: "test-fixture",
      });
      expect(annotated.clusters[0]?.suppressionReason).toBe(clusters[0]?.suppressionReason);
      expect(annotated.clusters[0]?.llm).toEqual(clusters[0]?.llm);
      const result: ScanResult = {
        schemaVersion: "clearance.report/v1",
        outcome: "clean",
        exitCode: 0,
        failOn: "high",
        startedAt: "2026-01-01T00:00:00Z",
        finishedAt: "2026-01-01T00:00:01Z",
        roots: [],
        detectors: [],
        ...annotated,
        coverage: [],
        skipped: [],
        errors: [],
        walk: {
          walked: 1,
          scannable: 1,
          skippedHarmless: 0,
          excludedByConfig: 0,
          archive: 0,
          oversize: 0,
          unreadable: 0,
        },
        artifacts: { manifest: "", markdown: "", html: "" },
      };
      expect(publicManifest(result)).toMatchObject({
        clusters: [{ effectiveStatus: "suppressed", policyExclusion: "test-fixture" }],
      });
      for (const showSuppressed of [false, true]) {
        const options = { showSuppressed, showHistoryCommits: false };
        for (const report of [renderMarkdown(result, options), renderHtml(result, options)]) {
          expect(report).toContain("Policy-excluded test fixtures");
          expect(report).toContain(`${reason}; policy: test-fixture`);
          expect(report.split(clusters[0]!.clusterId)).toHaveLength(2);
          expect(report).toContain("1 findings suppressed (shown above)");
        }
      }
    },
  );
  it("keeps mixed production/test clusters blocking at their existing severity", () => {
    const historyFixture = {
      ...occurrence("tests/a.ts"),
      source: { kind: "git" as const, commit: "a".repeat(40) },
    };
    const mixed = policy([historyFixture, occurrence("src/a.ts")], true);
    expect(mixed.clusters).toHaveLength(1);
    expect(mixed.clusters[0]).toMatchObject({
      pathContext: "mixed",
      effectiveStatus: "open",
      policyExcludedOccurrenceIds: ["tests/a.ts"],
    });
    expect(outcome(mixed.clusters)).toBe("denied");
    const lowProduction = policy(
      [{ ...historyFixture, severity: "critical" }, occurrence("src/a.ts", "low")],
      true,
    );
    expect(lowProduction.clusters[0]?.effectiveSeverity).toBe("critical");
    expect(outcome(lowProduction.clusters)).toBe("denied");
  });
  it("still sends test findings for validation, displays labels by default, and never hides policy exclusions", async () => {
    const dir = tree({ "tests/current.env": `STRIPE_KEY=${STRIPE_LIVE}\n` });
    const validateBatch = vi.fn(
      async (request: { batchId: string; clusters: Array<{ clusterId: string }> }) => ({
        batchId: request.batchId,
        verdicts: request.clusters.map((c) => ({
          clusterId: c.clusterId,
          status: "confirmed" as const,
          confidence: 0.9,
          rationale: "credential-shaped value",
        })),
      }),
    );
    const before = (
      await runOn(dir, ["--no-native", "--no-trufflehog", "--llm"], {
        llmRuntime: { validateBatch },
      })
    ).result;
    expect(before.outcome).toBe("denied");
    expect(before.clusters.every((c) => c.pathContext === "test-fixture")).toBe(true);
    expect(validateBatch).toHaveBeenCalled();
    const options = { showSuppressed: false, showHistoryCommits: false };
    expect(renderMarkdown(before, options)).toContain("Potential test fixtures (still counted)");
    expect(renderMarkdown(before, options)).toContain(
      "No current findings outside the test-only section below.",
    );
    expect(renderHtml(before, options)).toContain("<th>Presence</th>");
    expect(renderHtml(before, options)).toContain("<td>current</td>");
    expect(publicManifest(before)).toMatchObject({
      clusters: before.clusters.map(() => ({
        pathContext: "test-fixture",
        effectiveStatus: "open",
      })),
    });
    expect(renderHtml(before, options)).toContain("Potential test fixtures (still counted)");
    validateBatch.mockClear();
    const after = (
      await runOn(dir, ["--no-native", "--no-trufflehog", "--llm", "--exclude-test-fixtures"], {
        llmRuntime: { validateBatch },
      })
    ).result;
    expect(validateBatch).toHaveBeenCalled();
    expect(after.outcome).toBe("clean");
    expect(
      after.clusters.every(
        (c) => c.effectiveStatus === "policy_excluded" && c.llm?.status === "confirmed",
      ),
    ).toBe(true);
    expect(renderMarkdown(after, options)).toContain("Policy-excluded test fixtures");
    expect(renderHtml(after, options)).toContain("Policy-excluded test fixtures");
    expect(JSON.stringify(publicManifest(after))).toContain('"policyExclusion":"test-fixture"');
    expect(publicManifest(after)).toMatchObject({
      clusters: after.clusters.map(() => ({
        pathContext: "test-fixture",
        effectiveStatus: "policy_excluded",
      })),
    });
  }, 30_000);
  it("retains both external scanners' current/history fixture findings and mixed production locations", async () => {
    const secret = `STRIPE_KEY=${STRIPE_LIVE}\n`;
    const dir = tree({
      "tests/deleted.env": secret,
      "tests/current.env": secret,
      "production.env": secret,
    });
    initRepo(dir);
    git(dir, ["add", "."]);
    git(dir, ["commit", "-m", "fixtures and production"]);
    fs.rmSync(path.join(dir, "tests/deleted.env"));
    git(dir, ["add", "."]);
    git(dir, ["commit", "-m", "delete fixture"]);
    const { result } = await runOn(dir, [
      "--gitleaks-history",
      "--trufflehog-history",
      "--no-llm",
      "--exclude-test-fixtures",
    ]);
    expect(result.detectors.filter((d) => d.enabled).every((d) => d.status === "completed")).toBe(
      true,
    );
    expect(
      result.occurrences.some(
        (o) =>
          o.path === "tests/deleted.env" &&
          o.source.kind === "git" &&
          o.policyExclusion === "test-fixture",
      ),
    ).toBe(true);
    expect(
      new Set(
        result.occurrences.filter((o) => o.path === "tests/current.env").map((o) => o.scanner),
      ),
    ).toEqual(new Set(["gitleaks", "trufflehog"]));
    expect(result.occurrences.some((o) => o.path === "production.env" && !o.policyExclusion)).toBe(
      true,
    );
    expect(result.outcome).toBe("denied");
    expect(
      result.clusters.some((c) => c.pathContext === "mixed" && c.effectiveStatus === "open"),
    ).toBe(true);
  }, 60_000);
});
