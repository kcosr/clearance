import {
  outcomeExitCode,
  severityRank,
  type Cluster,
  type CoverageFinding,
  type DetectorResult,
  type Outcome,
  type Severity,
} from "./types.js";

export function decideOutcome(input: {
  clusters: Cluster[];
  coverage: CoverageFinding[];
  detectors: DetectorResult[];
  errors: string[];
  failOn: Severity;
  llmFailed?: boolean;
}): { outcome: Outcome; exitCode: 0 | 1 | 2 | 3 } {
  const detectorFailed = input.detectors.some((detector) => detector.enabled && detector.status === "failed");
  if (input.errors.length > 0 || detectorFailed || input.llmFailed) {
    return { outcome: "error", exitCode: 3 };
  }
  const open = input.clusters.filter((cluster) => cluster.effectiveStatus === "open");
  const denied = open.some((cluster) => severityRank(cluster.effectiveSeverity) >= severityRank(input.failOn));
  if (denied) return { outcome: "denied", exitCode: 2 };
  if (input.coverage.length > 0) return { outcome: "incomplete", exitCode: 2 };
  if (open.length > 0) return { outcome: "findings", exitCode: 1 };
  return { outcome: "clean", exitCode: 0 };
}

export { outcomeExitCode };
