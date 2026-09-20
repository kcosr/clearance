import type { AppConfig } from "./config.js";
import type { Cluster, Occurrence } from "./types.js";
import { maxSeverity } from "./types.js";

function matchesSuppress(candidate: string, config: AppConfig): boolean {
  const flags = config.suppress.ignoreCase ? "i" : undefined;
  const hay = config.suppress.ignoreCase ? candidate.toLowerCase() : candidate;
  for (const value of config.suppress.strings) {
    const needle = config.suppress.ignoreCase ? value.toLowerCase() : value;
    if (hay === needle) return true;
  }
  for (const pattern of config.suppress.patterns) {
    const regex = flags === undefined ? new RegExp(pattern) : new RegExp(pattern, flags);
    if (regex.test(candidate)) return true;
  }
  return false;
}

export function applySuppressions(
  occurrences: Occurrence[],
  clusters: Cluster[],
  config: AppConfig,
): { occurrences: Occurrence[]; clusters: Cluster[] } {
  const matchedIds = new Set(
    occurrences
      .filter(
        (occ) =>
          occ.extraction === "exact" &&
          occ.candidate !== undefined &&
          matchesSuppress(occ.candidate, config),
      )
      .map((occ) => occ.occurrenceId),
  );
  const suppressedIds = new Set(matchedIds);
  // A cluster may contain an inexact corroborating hit that was joined to one
  // unambiguous exact candidate by location. Once that exact candidate is
  // allowlisted, suppress the whole correlated finding rather than leave the
  // scanner fallback behind as a duplicate open row.
  for (const cluster of clusters) {
    if (!cluster.occurrenceIds.some((id) => matchedIds.has(id))) continue;
    for (const id of cluster.occurrenceIds) suppressedIds.add(id);
  }
  const nextOcc = occurrences.map((occ) => {
    if (!suppressedIds.has(occ.occurrenceId)) return occ;
    return { ...occ, suppressed: true as const, suppressionReason: "allowlisted" as const };
  });

  const nextClusters = clusters.map((cluster) => {
    const members = nextOcc.filter((occ) => cluster.occurrenceIds.includes(occ.occurrenceId));
    const allSuppressed = members.length > 0 && members.every((occ) => occ.suppressed);
    if (!allSuppressed) {
      const open = members.filter((occ) => !occ.suppressed);
      return {
        ...cluster,
        effectiveStatus: "open" as const,
        effectiveSeverity: open.length > 0 ? maxSeverity(open.map((occ) => occ.severity)) : cluster.severity,
      };
    }
    return {
      ...cluster,
      effectiveStatus: "suppressed" as const,
      suppressionReason: "allowlisted" as const,
    };
  });

  return { occurrences: nextOcc, clusters: nextClusters };
}
