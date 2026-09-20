import type { Cluster, ScanResult } from "../types.js";

function pluralCommits(count: number): string {
  return `${count} commit${count === 1 ? "" : "s"}`;
}

/** Table cells must not break the row; scanner text can contain pipes. */
function cell(value: string | undefined): string {
  if (!value) return "—";
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/** Why a cluster is suppressed: an admin allowlist, or an applied LLM verdict. */
export function suppressionReason(cluster: Cluster): string {
  const underlying =
    cluster.suppressionReason ??
    (cluster.llm?.status === "false_positive" && !cluster.llm.advisory
      ? "llm false_positive"
      : undefined);
  return (
    [underlying, cluster.policyExclusion ? `policy: ${cluster.policyExclusion}` : undefined]
      .filter(Boolean)
      .join("; ") || "—"
  );
}

type RowOptions = {
  showHistoryCommits: boolean;
  includeRaw: boolean;
  showHistory: boolean;
  showReason?: boolean;
};

function clusterRow(cluster: Cluster, options: RowOptions): string {
  const { showHistoryCommits, includeRaw, showHistory } = options;
  const found = cluster.foundBy.join("+") || "—";
  const commits = showHistoryCommits
    ? cluster.locations
        .map((loc) => loc.commit)
        .filter((commit): commit is string => Boolean(commit))
        .map((commit) => commit.slice(0, 8))
        .join(",")
    : cluster.presence === "current"
      ? ""
      : pluralCommits(cluster.locations.filter((loc) => loc.commit).length);
  // The rationale is the useful half of the verdict; HTML renders it as
  // secondary text, and Markdown was dropping it entirely.
  const llm = cluster.llm
    ? `${cluster.llm.status}${cluster.llm.advisory ? " (advisory)" : ""}` +
      (cluster.llm.rationale ? ` — ${cell(cluster.llm.rationale)}` : "")
    : "—";
  // Prefer the full line: it is readable even when we could not isolate a token.
  const raw = includeRaw ? ` \`${cell(cluster.match ?? cluster.candidate)}\` |` : "";
  const history = showHistory ? ` ${cell(commits)} |` : "";
  const context =
    cluster.pathContext === "test-fixture"
      ? "test-like path"
      : cluster.pathContext === "mixed"
        ? "mixed test/other paths"
        : "—";
  const reason = options.showReason ? ` ${cell(suppressionReason(cluster))} |` : "";
  return (
    `| ${cluster.clusterId} | ${cluster.rootId} | \`${cell(`${cluster.path}:${cluster.lineStart}`)}\` |` +
    ` ${cluster.presence} | ${context} | ${cluster.effectiveSeverity} | ${cell(cluster.description)} |` +
    ` ${found} | ${cluster.effectiveStatus} | ${llm} |${history}${reason}${raw}`
  );
}

export function renderMarkdown(
  result: ScanResult,
  options: { showSuppressed: boolean; showHistoryCommits: boolean; includeRaw?: boolean },
): string {
  const includeRaw = options.includeRaw === true;
  // Suppressed clusters get their own section rather than being mixed into the
  // findings tables, so what is still open stays unambiguous.
  const open = result.clusters.filter((cluster) => cluster.effectiveStatus === "open");
  const suppressedClusters = result.clusters.filter(
    (cluster) => cluster.effectiveStatus === "suppressed" && !cluster.policyExclusion,
  );
  const testOnly = open.filter((cluster) => cluster.pathContext === "test-fixture");
  const policyExcluded = result.clusters.filter((cluster) => cluster.policyExclusion !== undefined);
  const otherOpen = open.filter((cluster) => cluster.pathContext !== "test-fixture");
  const current = otherOpen.filter((cluster) => cluster.presence !== "historical");
  const historical = otherOpen.filter((cluster) => cluster.presence === "historical");
  const suppressed = result.clusters.filter((c) => c.effectiveStatus === "suppressed").length;
  const hiddenSuppressed = options.showSuppressed ? 0 : suppressedClusters.length;
  const lines = [
    `# Clearance report`,
    ``,
    ...(includeRaw
      ? [
          `> **This report may contain secrets.** It was generated with \`--include-raw\`.`,
          `> Treat it as credential material: do not commit it, attach it to tickets, or publish it to CI logs.`,
          ``,
        ]
      : []),
    `Outcome: **${result.outcome}**`,
    `Fail on: ${result.failOn}`,
    `Started: ${result.startedAt}`,
    `Finished: ${result.finishedAt}`,
    ``,
    `## Roots`,
    ``,
    ...result.roots.map((root) => `- \`${root.rootId}\``),
    ``,
    `## Detectors`,
    ``,
    ...result.detectors.map((detector) => {
      const extra = detector.error
        ? ` (${detector.error})`
        : detector.version
          ? ` ${detector.version}`
          : "";
      return `- ${detector.name}: ${detector.status}${extra}`;
    }),
    ``,
    `## Summary`,
    ``,
    `- walked: ${result.walk.walked}`,
    `- scannable: ${result.walk.scannable}`,
    `- skippedHarmless: ${result.walk.skippedHarmless}`,
    `- archive: ${result.walk.archive}`,
    `- oversize: ${result.walk.oversize}`,
    `- unreadable: ${result.walk.unreadable}`,
    `- clusters: ${result.clusters.length}`,
    `- test-like paths only: ${result.clusters.filter((c) => c.pathContext === "test-fixture").length}`,
    `- mixed test/other paths: ${result.clusters.filter((c) => c.pathContext === "mixed").length}`,
    `- newly policy-excluded test findings: ${policyExcluded.filter((c) => c.effectiveStatus === "policy_excluded").length}; already suppressed: ${policyExcluded.filter((c) => c.effectiveStatus === "suppressed").length}`,
    `- coverage findings: ${result.coverage.length}`,
    ``,
  ];
  // Nothing historical can exist with no history detector enabled, so the
  // section and the column are omitted rather than rendered empty.
  const showHistory =
    result.detectors.some((d) => d.name.endsWith("-history") && d.enabled) ||
    open.some((c) => c.presence === "historical");
  const header =
    `| ID | Root | Path | Presence | Path context | Severity | Description | Found by | Status | LLM |` +
    (showHistory ? ` History |` : ``) +
    (includeRaw ? ` Match |` : ``);
  const sep =
    `|---|---|---|---|---|---|---|---|---|---|` +
    (showHistory ? `---|` : ``) +
    (includeRaw ? `---|` : ``);
  const rowOptions: RowOptions = {
    showHistoryCommits: options.showHistoryCommits,
    includeRaw,
    showHistory,
  };
  const rows = (list: Cluster[]): string[] =>
    list.map((cluster) => clusterRow(cluster, rowOptions));
  lines.push(`## Current (working tree)`, ``);
  if (current.length === 0) {
    lines.push(
      testOnly.some((c) => c.presence !== "historical")
        ? "No current findings outside the test-only section below."
        : "No current findings.",
      ``,
    );
  } else {
    lines.push(header, sep, ...rows(current), ``);
  }
  if (showHistory) {
    lines.push(`## Historical (not in working tree)`, ``);
    if (historical.length === 0) {
      lines.push(
        testOnly.some((c) => c.presence === "historical")
          ? "No historical findings outside the test-only section below."
          : "No historical findings.",
        ``,
      );
    } else {
      lines.push(header, sep, ...rows(historical), ``);
    }
  }
  if (testOnly.length) {
    lines.push(
      "## Potential test fixtures (still counted)",
      "",
      "Identified by path only; this does not prove credentials are fake. These findings still contribute to the outcome.",
      "",
      header,
      sep,
      ...rows(testOnly),
      "",
    );
  }
  if (policyExcluded.length) {
    lines.push(
      "## Policy-excluded test fixtures",
      "",
      "Reason: test-fixture. Scanned and classified normally; covered by explicit outcome policy. Existing suppressions and LLM verdicts remain independent.",
      "",
      `| ID | Root | Path | Presence | Path context | Severity | Description | Found by | Status | LLM |` +
        (showHistory ? ` History |` : ``) +
        ` Reason |` +
        (includeRaw ? ` Match |` : ``),
      `|---|---|---|---|---|---|---|---|---|---|` +
        (showHistory ? `---|` : ``) +
        `---|` +
        (includeRaw ? `---|` : ``),
      ...policyExcluded.map((cluster) => clusterRow(cluster, { ...rowOptions, showReason: true })),
      "",
    );
  }
  if (result.classifier) {
    lines.push(
      "## Current-file classifier coverage",
      "",
      "Git history is not screened by this classifier.",
      "",
    );
    for (const row of result.classifier.files)
      lines.push(
        `- ${cell(row.rootId)} ${cell(row.path)}: ${row.status}${row.reason ? ` (${cell(row.reason)})` : ""}`,
      );
    lines.push("");
  }
  if (result.coverage.length > 0) {
    lines.push(`## Coverage`, ``);
    for (const item of result.coverage) {
      lines.push(`- ${item.rootId} \`${item.path}\` (${item.reason})`);
    }
    lines.push(``);
  }
  if (options.showSuppressed && suppressedClusters.length > 0) {
    const suppressedHeader =
      `| ID | Root | Path | Presence | Path context | Severity | Description | Found by | Status | LLM |` +
      (showHistory ? ` History |` : ``) +
      ` Reason |` +
      (includeRaw ? ` Match |` : ``);
    const suppressedSep =
      `|---|---|---|---|---|---|---|---|---|---|` +
      (showHistory ? `---|` : ``) +
      `---|` +
      (includeRaw ? `---|` : ``);
    lines.push(
      `## Suppressed`,
      ``,
      `Not counted toward \`failOn\`.`,
      ``,
      suppressedHeader,
      suppressedSep,
      ...suppressedClusters.map((cluster) =>
        clusterRow(cluster, { ...rowOptions, showReason: true }),
      ),
      ``,
    );
  }
  // Always printed, including at zero: the reader needs to know nothing was
  // hidden from them, not merely be told when something was.
  lines.push(
    suppressed === 0
      ? `0 findings suppressed.`
      : `${suppressed} findings suppressed${hiddenSuppressed ? ` (${hiddenSuppressed} hidden; use --show-suppressed)` : " (shown above)"}.`,
    ``,
  );
  if (result.errors.length > 0) {
    lines.push(`## Errors`, ``, ...result.errors.map((error) => `- ${error}`), ``);
  }
  return lines.join("\n");
}
