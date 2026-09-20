export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const OUTCOMES = ["clean", "findings", "denied", "incomplete", "error"] as const;
export type Outcome = (typeof OUTCOMES)[number];

export type ScannerName = "native" | "gitleaks" | "trufflehog" | "classifier";
export type DetectorName =
  | "classifier"
  | "native"
  | "gitleaks"
  | "gitleaks-history"
  | "trufflehog"
  | "trufflehog-history";

export type DetectorStatus = "completed" | "partial" | "failed" | "skipped";

export type Presence = "current" | "historical" | "current_and_historical";
export type CoveragePolicy = "skip" | "incomplete";
export type ExtractionStatus = "exact" | "inexact" | "unavailable";

export type OccurrenceSource = { kind: "workingTree" } | { kind: "git"; commit: string };

export type Occurrence = {
  occurrenceId: string;
  /** Path heuristic only; does not assert that a credential is fake. */
  pathContext?: "test-fixture";
  policyExclusion?: "test-fixture";
  matchKind?: "filename";
  /** Half-open offsets in original UTF-8 bytes, when supplied by classifier. */
  byteStart?: number;
  byteEnd?: number;
  scanner: ScannerName;
  rootId: string;
  path: string;
  lineStart: number;
  lineEnd: number;
  columnStart?: number;
  columnEnd?: number;
  ruleId: string;
  category: string;
  severity: Severity;
  message?: string;
  source: OccurrenceSource;
  suppressed?: boolean;
  suppressionReason?: "allowlisted";
  extraction: ExtractionStatus;
  /** Canonical secret identity used for correlation and suppression. */
  candidate?: string;
  candidateFingerprint?: string;
  evidenceText?: string;
  /**
   * The full source line the match sits on, captured regardless of whether we
   * could isolate a candidate. This is what we show and what the model judges;
   * `candidate` exists only to fingerprint, correlate, and suppress.
   */
  matchLine?: string;
};

export type ClusterLocation = {
  path: string;
  commit?: string;
  lineStart: number;
  scanners: ScannerName[];
};

export type ClusterVerdict = {
  status: "confirmed" | "false_positive" | "uncertain" | "needs_context" | "unreviewed";
  confidence?: number;
  severityOverride?: Severity;
  rationale?: string;
  duplicateOf?: string;
  advisory?: boolean;
};

export type Cluster = {
  clusterId: string;
  pathContext?: "test-fixture" | "mixed";
  testFixtureOccurrenceIds?: string[];
  policyExcludedOccurrenceIds?: string[];
  policyExclusion?: "test-fixture";
  secretId: string;
  presence: Presence;
  rootId: string;
  path: string;
  lineStart: number;
  lineEnd: number;
  category: string;
  severity: Severity;
  /** Human-readable rule/detector text; first non-empty occurrence `message`. */
  description?: string;
  foundBy: ScannerName[];
  notFoundBy: ScannerName[];
  occurrenceIds: string[];
  locations: ClusterLocation[];
  candidateFingerprint?: string;
  /** Exact extracted candidate. Only published when `[report].includeRaw`. */
  candidate?: string;
  /** Full source line. Contains the secret; only published when `includeRaw`. */
  match?: string;
  evidence?: ExtractionStatus;
  llm?: ClusterVerdict;
  effectiveStatus: "open" | "suppressed" | "policy_excluded";
  effectiveSeverity: Severity;
  suppressionReason?: "allowlisted";
};

export type CoverageFinding = {
  rootId: string;
  path: string;
  reason: "archive" | "oversize" | "unreadable" | "drift" | "classifier-incomplete";
};

export type SkippedFile = {
  rootId: string;
  path: string;
  reason: "harmless" | "archive" | "oversize" | "unreadable" | "symlink-escape" | "excluded";
};

export type DetectorResult = {
  name: DetectorName;
  enabled: boolean;
  status: DetectorStatus;
  version?: string;
  error?: string;
};

export type RootRecord = {
  rootId: string;
  supplied: string;
  realPath: string;
  git: { kind: "none" | "worktree" | "bare"; topLevel?: string; reason?: string };
};

export type WalkSummary = {
  walked: number;
  scannable: number;
  skippedHarmless: number;
  excludedByConfig: number;
  archive: number;
  oversize: number;
  unreadable: number;
};

export type LlmStatus = "skipped" | "complete" | "partial" | "failed";

export type ClassifierCoverage = {
  rootId: string;
  path: string;
  status: "completed" | "empty" | "excluded" | "failed";
  reason?: string;
};

export type ScanResult = {
  classifier?: { policyDigest: string; files: ClassifierCoverage[] };
  schemaVersion: "clearance.report/v1";
  outcome: Outcome;
  exitCode: 0 | 1 | 2 | 3;
  failOn: Severity;
  startedAt: string;
  finishedAt: string;
  roots: RootRecord[];
  detectors: DetectorResult[];
  llm?: {
    enabled: true;
    mode: "validate";
    model: string;
    api: string;
    status: LlmStatus;
  };
  occurrences: Occurrence[];
  clusters: Cluster[];
  coverage: CoverageFinding[];
  skipped: SkippedFile[];
  walk: WalkSummary;
  errors: string[];
  artifacts: { manifest: string; markdown: string; html: string } | null;
};

export function severityRank(severity: Severity): number {
  return { low: 1, medium: 2, high: 3, critical: 4 }[severity];
}

export function maxSeverity(values: Severity[]): Severity {
  return values.reduce(
    (best, next) => (severityRank(next) > severityRank(best) ? next : best),
    "low",
  );
}

export function outcomeExitCode(outcome: Outcome): 0 | 1 | 2 | 3 {
  switch (outcome) {
    case "clean":
      return 0;
    case "findings":
      return 1;
    case "denied":
    case "incomplete":
      return 2;
    case "error":
      return 3;
  }
}
