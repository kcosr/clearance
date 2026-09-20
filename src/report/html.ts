import type { Cluster, DetectorResult, ScanResult } from "../types.js";
import { escapeHtml } from "./html-escape.js";

const STYLE = `
body {
  margin: 0;
  padding: 2rem 2.25rem 4rem;
  background: #fff;
  color: #111;
  font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
}
/* Prose and the small tables keep a readable measure; only the finding tables,
   which carry the most columns, are given the whole window. */
main { max-width: 1180px; }
.scroll.findings { max-width: none; width: calc(100vw - 4.5rem); }
.scroll.findings table { min-width: 100%; }
h1 { font-size: 1.75rem; font-weight: 700; margin: 0 0 1.25rem; }
h2 { font-size: 1.15rem; font-weight: 700; margin: 2.25rem 0 0.6rem; }
p { margin: 0.4rem 0; }
.meta { margin-bottom: 0.35rem; }
.meta strong { font-weight: 700; }
.stamp { color: #555; font-size: 0.9rem; margin-top: 0.9rem; }
.note {
  border: 1px solid #d8b9b5; background: #fdf3f2; border-radius: 3px;
  padding: 0.7rem 0.9rem; margin: 1rem 0; font-size: 0.92rem;
}
.note strong { display: block; margin-bottom: 0.15rem; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; margin: 0.35rem 0 0.5rem; font-size: 0.92rem; }
table.wide { width: 100%; }
th, td { border: 1px solid #ddd; padding: 0.45rem 0.7rem; text-align: left; vertical-align: top; }
th { background: #f5f5f5; font-weight: 700; white-space: nowrap; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; }
td.id, td.path, td.hist { white-space: nowrap; }
/* Long values wrap in place; nowrap overflows the cell and clips characters. */
td.secret { word-break: break-all; }
td.desc { color: #444; min-width: 24rem; }
td.llm { min-width: 18rem; }
.sev-critical, .sev-high { font-weight: 700; }
.muted { color: #666; }
.rationale { display: block; color: #555; font-size: 0.86rem; margin-top: 0.1rem; }
.empty { color: #666; margin: 0.35rem 0 0.5rem; }
.footnote { color: #555; font-size: 0.9rem; margin-top: 1.75rem; }
@media print {
  body { padding: 0; font-size: 11pt; }
  .scroll { overflow: visible; }
  tr { break-inside: avoid; }
}
`;

function sevClass(severity: string): string {
  return `sev-${severity}`;
}

function commitsFor(cluster: Cluster, showHistoryCommits: boolean): string {
  const commits = cluster.locations
    .map((loc) => loc.commit)
    .filter((commit): commit is string => Boolean(commit));
  if (commits.length === 0) return "";
  if (showHistoryCommits) return commits.map((commit) => commit.slice(0, 8)).join(", ");
  return `${commits.length} commit${commits.length === 1 ? "" : "s"}`;
}

/** Why a cluster is suppressed: an admin allowlist, or an applied LLM verdict. */
function suppressionReason(cluster: Cluster): string {
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

type TableOptions = {
  showHistoryCommits: boolean;
  includeRaw: boolean;
  multiRoot: boolean;
  showHistory: boolean;
  showReason?: boolean;
};

function findingsTable(clusters: Cluster[], options: TableOptions, emptyText: string): string {
  if (clusters.length === 0) return `<p class="empty">${escapeHtml(emptyText)}</p>`;
  const head = [
    "<th>ID</th>",
    options.multiRoot ? "<th>Root</th>" : "",
    "<th>Path</th>",
    "<th>Presence</th>",
    "<th>Path context</th>",
    "<th>Severity</th>",
    "<th>Description</th>",
    "<th>Found by</th>",
    "<th>Status</th>",
    "<th>LLM</th>",
    options.showHistory ? "<th>History</th>" : "",
    options.showReason ? "<th>Reason</th>" : "",
    options.includeRaw ? "<th>Match</th>" : "",
  ].join("");
  const body = clusters
    .map((cluster) => {
      const commits = commitsFor(cluster, options.showHistoryCommits);
      const llm = cluster.llm
        ? `${cluster.llm.status}${cluster.llm.advisory ? " (advisory)" : ""}`
        : "—";
      const rationale = cluster.llm?.rationale
        ? `<span class="rationale">${escapeHtml(cluster.llm.rationale)}</span>`
        : "";
      const status = escapeHtml(cluster.effectiveStatus);
      // The line is what an operator reads; the isolated candidate is only
      // shown when we could actually prove which bytes it is.
      const secret =
        cluster.match === undefined
          ? cluster.candidate === undefined
            ? "—"
            : `<code>${escapeHtml(cluster.candidate)}</code>`
          : `<code>${escapeHtml(cluster.match)}</code>`;
      return `<tr>
<td class="id"><code>${escapeHtml(cluster.clusterId)}</code></td>
${options.multiRoot ? `<td><code>${escapeHtml(cluster.rootId)}</code></td>` : ""}
<td class="path"><code>${escapeHtml(cluster.path)}:${cluster.lineStart}</code></td>
<td>${escapeHtml(cluster.presence)}</td>
<td>${escapeHtml(cluster.pathContext === "test-fixture" ? "test-like path" : cluster.pathContext === "mixed" ? "mixed test/other paths" : "—")}</td>
<td class="${sevClass(cluster.effectiveSeverity)}">${escapeHtml(cluster.effectiveSeverity)}</td>
<td class="desc">${escapeHtml(cluster.description ?? "—")}</td>
<td>${escapeHtml(cluster.foundBy.join("+") || "—")}</td>
<td>${status}</td>
<td class="llm">${escapeHtml(llm)}${rationale}</td>
${options.showHistory ? `<td class="hist">${escapeHtml(commits || "—")}</td>` : ""}
${options.showReason ? `<td>${escapeHtml(suppressionReason(cluster))}</td>` : ""}
${options.includeRaw ? `<td class="secret">${secret}</td>` : ""}
</tr>`;
    })
    .join("\n");
  return `<div class="scroll findings"><table class="wide">
<thead><tr>${head}</tr></thead>
<tbody>
${body}
</tbody>
</table></div>`;
}

function detectorsTable(detectors: DetectorResult[]): string {
  if (detectors.length === 0) return `<p class="empty">No detectors ran.</p>`;
  const body = detectors
    .map(
      (detector) => `<tr>
<td><code>${escapeHtml(detector.name)}</code></td>
<td>${escapeHtml(detector.status)}</td>
<td>${escapeHtml(detector.version ?? "—")}</td>
<td>${escapeHtml(detector.error ?? "—")}</td>
</tr>`,
    )
    .join("\n");
  return `<div class="scroll"><table>
<thead><tr><th>Detector</th><th>Status</th><th>Version</th><th>Note</th></tr></thead>
<tbody>
${body}
</tbody>
</table></div>`;
}

function countsTable(result: ScanResult): string {
  const rows: Array<[string, number]> = [
    ["Walked", result.walk.walked],
    ["Scannable", result.walk.scannable],
    ["Skipped as harmless", result.walk.skippedHarmless],
    ["Archives", result.walk.archive],
    ["Oversize", result.walk.oversize],
    ["Unreadable", result.walk.unreadable],
    ["Excluded by config", result.walk.excludedByConfig],
    ["Clusters", result.clusters.length],
    ["Coverage findings", result.coverage.length],
  ];
  const body = rows
    .map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td class="num">${value}</td></tr>`)
    .join("\n");
  return `<table><tbody>\n${body}\n</tbody></table>`;
}

function coverageTable(result: ScanResult): string {
  if (result.coverage.length === 0) return "";
  const body = result.coverage
    .map(
      (item) => `<tr>
<td><code>${escapeHtml(item.rootId)}</code></td>
<td class="path"><code>${escapeHtml(item.path)}</code></td>
<td>${escapeHtml(item.reason)}</td>
</tr>`,
    )
    .join("\n");
  return `<h2>Coverage</h2>
<p class="muted">Files the scan could not inspect. The run cannot be reported clean while these exist.</p>
<div class="scroll"><table>
<thead><tr><th>Root</th><th>Path</th><th>Reason</th></tr></thead>
<tbody>
${body}
</tbody>
</table></div>`;
}

function classifierTable(result: ScanResult): string {
  if (!result.classifier) return "";
  const rows = result.classifier.files
    .map(
      (row) =>
        `<tr><td>${escapeHtml(row.rootId)}</td><td>${escapeHtml(row.path)}</td><td>${escapeHtml(row.status)}</td><td>${escapeHtml(row.reason ?? "")}</td></tr>`,
    )
    .join("\n");
  return `<h2>Current-file classifier coverage</h2><p>Git history is not screened by this classifier.</p><div class="scroll"><table><thead><tr><th>Root</th><th>Path</th><th>Status</th><th>Reason</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

export function renderHtml(
  result: ScanResult,
  options: { showSuppressed: boolean; showHistoryCommits: boolean; includeRaw?: boolean },
): string {
  const includeRaw = options.includeRaw === true;
  // Suppressed clusters get their own section rather than being mixed into the
  // findings tables, so what is still open stays unambiguous.
  const open = result.clusters.filter((c) => c.effectiveStatus === "open");
  const suppressedClusters = result.clusters.filter(
    (c) => c.effectiveStatus === "suppressed" && !c.policyExclusion,
  );
  const testOnly = open.filter((c) => c.pathContext === "test-fixture");
  const policyExcluded = result.clusters.filter((c) => c.policyExclusion !== undefined);
  const otherOpen = open.filter((c) => c.pathContext !== "test-fixture");
  const current = otherOpen.filter((c) => c.presence !== "historical");
  const historical = otherOpen.filter((c) => c.presence === "historical");
  const suppressed = result.clusters.filter((c) => c.effectiveStatus === "suppressed").length;
  const hiddenSuppressed = options.showSuppressed ? 0 : suppressedClusters.length;
  const multiRoot = result.roots.length > 1;
  // With no history detector enabled there is nothing historical to show, so the
  // section and the column are omitted rather than rendered empty.
  const showHistory =
    result.detectors.some((d) => d.name.endsWith("-history") && d.enabled) ||
    open.some((c) => c.presence === "historical");
  const tableOptions: TableOptions = {
    showHistoryCommits: options.showHistoryCommits,
    includeRaw,
    multiRoot,
    showHistory,
  };
  const suppressedSection =
    options.showSuppressed && suppressedClusters.length > 0
      ? `<h2>Suppressed</h2>
<p class="muted">Not counted toward <code>failOn</code>.</p>
${findingsTable(suppressedClusters, { ...tableOptions, showReason: true }, "None.")}`
      : "";

  const fixtureSections =
    `<p>Test-like paths only: ${result.clusters.filter((c) => c.pathContext === "test-fixture").length}; mixed test/other paths: ${result.clusters.filter((c) => c.pathContext === "mixed").length}; newly policy-excluded: ${policyExcluded.filter((c) => c.effectiveStatus === "policy_excluded").length}; already suppressed under this policy: ${policyExcluded.filter((c) => c.effectiveStatus === "suppressed").length}.</p>` +
    (testOnly.length
      ? `<h2>Potential test fixtures (still counted)</h2><p>Identified by path only; this does not prove credentials are fake. These findings still contribute to the outcome.</p>${findingsTable(testOnly, tableOptions, "None.")}`
      : "") +
    (policyExcluded.length
      ? `<h2>Policy-excluded test fixtures</h2><p>Reason: test-fixture. Scanned and classified normally; covered by explicit outcome policy. Existing suppressions and LLM verdicts remain independent.</p>${findingsTable(policyExcluded, { ...tableOptions, showReason: true }, "None.")}`
      : "");

  const rawNotice = includeRaw
    ? `<div class="note"><strong>This report may contain secrets.</strong>
Generated with <code>--include-raw</code>. Treat this file as credential material: do not commit it, attach it to a ticket, or publish it to CI logs.</div>`
    : "";

  const errors =
    result.errors.length === 0
      ? ""
      : `<h2>Errors</h2><ul>${result.errors.map((error) => `<li>${escapeHtml(error)}</li>`).join("")}</ul>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Clearance report — ${escapeHtml(result.outcome)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
<h1>Clearance report</h1>
${rawNotice}
<p class="meta"><strong>Outcome: ${escapeHtml(result.outcome)}</strong> (exit ${result.exitCode})</p>
<p class="meta">Fail on: ${escapeHtml(result.failOn)}</p>
<p class="meta">Roots: ${result.roots.map((root) => `<code>${escapeHtml(root.rootId)}</code>`).join(", ")}</p>
<p class="meta">LLM: ${
    result.llm
      ? `${escapeHtml(result.llm.mode)} (${escapeHtml(result.llm.status)}) · <code>${escapeHtml(result.llm.model)}</code>`
      : "off"
  }</p>
<p class="stamp">Started: ${escapeHtml(result.startedAt)}<br>Finished: ${escapeHtml(result.finishedAt)}</p>

<h2>Detectors</h2>
${detectorsTable(result.detectors)}

<h2>Summary</h2>
${countsTable(result)}

<h2>Current (working tree)</h2>
${findingsTable(current, tableOptions, testOnly.some((c) => c.presence !== "historical") ? "No working-tree findings outside the test-only section below." : "No findings in the working tree.")}

${
  showHistory
    ? `<h2>Historical (not in working tree)</h2>
${findingsTable(historical, tableOptions, testOnly.some((c) => c.presence === "historical") ? "No historical findings outside the test-only section below." : "No findings in local git history.")}`
    : ""
}

${fixtureSections}
${suppressedSection}
${classifierTable(result)}
${coverageTable(result)}
${errors}
<p class="footnote">${
    suppressed === 0
      ? "0 findings suppressed."
      : escapeHtml(
          `${suppressed} findings suppressed${hiddenSuppressed ? ` (${hiddenSuppressed} hidden; use --show-suppressed)` : " (shown above)"}.`,
        )
  }</p>
</main>
</body>
</html>
`;
}
