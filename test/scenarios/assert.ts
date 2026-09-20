import { expect } from "vitest";
import type { ScanResult } from "../../src/types.js";
import { assertNoFindingAbsolutes, assertNoSecretLeaks, readArtifacts } from "../helpers.js";

export function assertScenario(
  result: ScanResult,
  stdout: string,
  stderr: string,
  expected: { exit: number; outcome: ScanResult["outcome"] },
): ReturnType<typeof readArtifacts> {
  expect(result.exitCode).toBe(expected.exit);
  expect(result.outcome).toBe(expected.outcome);
  expect(stdout).toContain(`outcome: ${expected.outcome} (exit ${expected.exit})`);
  const artifacts = readArtifacts(result);
  assertNoSecretLeaks(artifacts.manifest, artifacts.markdown, artifacts.html, stdout, stderr);
  assertNoFindingAbsolutes(artifacts.manifest, artifacts.markdown, artifacts.html);
  JSON.parse(artifacts.manifest);
  return artifacts;
}
