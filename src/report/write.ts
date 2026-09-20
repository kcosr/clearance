import fs from "node:fs";
import path from "node:path";
import { severityRank, type ScanResult, type Severity } from "../types.js";
import { renderHtml } from "./html.js";
import { renderMarkdown } from "./markdown.js";
import { publicManifest } from "./public.js";

function atomicWrite(dest: string, contents: string): void {
  const tmp = `${dest}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, contents);
  fs.renameSync(tmp, dest);
}

export function writeArtifacts(
  result: ScanResult,
  outputDir: string,
  options: { showSuppressed: boolean; showHistoryCommits: boolean; includeRaw: boolean },
): { manifest: string; markdown: string; html: string } {
  const resolved = path.resolve(outputDir);
  fs.mkdirSync(resolved, { recursive: true });
  const dest = {
    manifest: path.join(resolved, "manifest.json"),
    markdown: path.join(resolved, "report.md"),
    html: path.join(resolved, "report.html"),
  };
  atomicWrite(
    dest.manifest,
    `${JSON.stringify(publicManifest(result, options.includeRaw), null, 2)}\n`,
  );
  atomicWrite(dest.markdown, renderMarkdown(result, options));
  atomicWrite(dest.html, renderHtml(result, options));
  return dest;
}

export function formatHumanSummary(result: ScanResult): string {
  const detectors = result.detectors
    .map((detector) => {
      const extra = detector.error ? `(${detector.error})` : "";
      return extra
        ? `${detector.name}=${detector.status}${extra}`
        : `${detector.name}=${detector.status}`;
    })
    .join(",");
  const open = result.clusters.filter((cluster) => cluster.effectiveStatus === "open");
  const current = result.clusters.filter((cluster) => cluster.presence !== "historical").length;
  const historical = result.clusters.filter((cluster) => cluster.presence === "historical").length;
  const llmCounts = countLlm(result);
  const llmLine = result.llm ? `llm: ${result.llm.mode}` : "llm: off";
  const clusterLine =
    llmCounts.length > 0
      ? `clusters: ${result.clusters.length} current=${current} historical=${historical} (${llmCounts.join(", ")})`
      : `clusters: ${result.clusters.length} current=${current} historical=${historical}`;
  const highestSeverity = open.reduce<Severity | undefined>(
    (highest, cluster) =>
      highest === undefined || severityRank(cluster.effectiveSeverity) > severityRank(highest)
        ? cluster.effectiveSeverity
        : highest,
    undefined,
  );
  const decision = result.outcome === "clean" ? "CLEARED" : "NOT CLEARED";
  const explanation = (() => {
    switch (result.outcome) {
      case "clean":
        return result.clusters.some((c) => c.effectiveStatus === "policy_excluded")
          ? `No unresolved findings remain in policy scope; ${result.clusters.filter((c) => c.effectiveStatus === "policy_excluded").length} test-path findings excluded by policy.`
          : "No unresolved findings were detected by the configured scanners.";
      case "findings":
        return "Potential secrets were found and require review.";
      case "denied":
        return "Potential secrets were found at or above the configured severity threshold.";
      case "incomplete":
        return "The scan was incomplete. Do not treat this repository as cleared.";
      case "error":
        return "The scan failed. Do not treat this repository as cleared.";
    }
  })();
  return [
    `CLEARANCE RESULT: ${decision}`,
    "",
    explanation,
    ...(open.length > 0 ? [`Open findings: ${open.length}`] : []),
    ...(highestSeverity === undefined ? [] : [`Highest severity: ${highestSeverity}`]),
    `Policy threshold: ${result.failOn}`,
    `Potential test fixtures: ${result.clusters.filter((c) => c.pathContext === "test-fixture").length} test-only, ${result.clusters.filter((c) => c.pathContext === "mixed").length} mixed with other paths; ${open.filter((c) => c.pathContext === "test-fixture").length} test-only findings still counted, ${result.clusters.filter((c) => c.effectiveStatus === "policy_excluded").length} newly excluded by policy, ${result.clusters.filter((c) => c.policyExclusion !== undefined && c.effectiveStatus === "suppressed").length} already suppressed.`,
    "",
    ...(result.artifacts
      ? [
          `Markdown report: ${result.artifacts.markdown}`,
          `HTML report: ${result.artifacts.html}`,
          `Machine-readable manifest: ${result.artifacts.manifest}`,
        ]
      : ["Report files: disabled"]),
    "",
    `outcome: ${result.outcome} (exit ${result.exitCode})`,
    `roots: ${result.roots.map((root) => root.realPath).join(" ")}`,
    `detectors: ${detectors || "none"}`,
    llmLine,
    clusterLine,
    "",
  ].join("\n");
}

function countLlm(result: ScanResult): string[] {
  const counts = new Map<string, number>();
  for (const cluster of result.clusters) {
    if (!cluster.llm) continue;
    counts.set(cluster.llm.status, (counts.get(cluster.llm.status) ?? 0) + 1);
  }
  return [...counts.entries()].map(([status, n]) => `${status} ${n}`);
}
