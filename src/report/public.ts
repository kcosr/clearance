import type { Cluster, Occurrence, ScanResult } from "../types.js";

export function publicOccurrence(occ: Occurrence): Record<string, unknown> {
  return {
    occurrenceId: occ.occurrenceId,
    ...(occ.pathContext ? { pathContext: occ.pathContext } : {}),
    ...(occ.policyExclusion ? { policyExclusion: occ.policyExclusion } : {}),
    ...(occ.byteStart === undefined ? {} : { byteStart: occ.byteStart, byteEnd: occ.byteEnd }),
    scanner: occ.scanner,
    rootId: occ.rootId,
    path: occ.path,
    lineStart: occ.lineStart,
    lineEnd: occ.lineEnd,
    ...(occ.columnStart === undefined ? {} : { columnStart: occ.columnStart }),
    ...(occ.columnEnd === undefined ? {} : { columnEnd: occ.columnEnd }),
    ruleId: occ.ruleId,
    category: occ.category,
    severity: occ.severity,
    ...(occ.message === undefined ? {} : { message: occ.message }),
    source: occ.source,
    ...(occ.suppressed === undefined ? {} : { suppressed: occ.suppressed }),
    ...(occ.suppressionReason === undefined ? {} : { suppressionReason: occ.suppressionReason }),
    extraction: occ.extraction,
    ...(occ.candidateFingerprint === undefined
      ? {}
      : { candidateFingerprint: occ.candidateFingerprint }),
  };
}

/**
 * `includeRaw` publishes the host-extracted candidate, and only for an `exact`
 * extraction — an `inexact` candidate may be surrounding text rather than the
 * secret, so publishing it would be both a leak and a lie.
 */
export function publicCluster(cluster: Cluster, includeRaw = false): Record<string, unknown> {
  const raw =
    includeRaw && cluster.evidence === "exact" && cluster.candidate !== undefined
      ? cluster.candidate
      : undefined;
  // The full line contains the secret, so it is gated exactly like `raw`. It is
  // published even when extraction was inexact — that is the case where it is
  // the only thing an operator has to work from.
  const match = includeRaw ? cluster.match : undefined;
  return {
    clusterId: cluster.clusterId,
    ...(cluster.pathContext
      ? {
          pathContext: cluster.pathContext,
          testFixtureOccurrenceIds: cluster.testFixtureOccurrenceIds,
        }
      : {}),
    ...(cluster.policyExclusion ? { policyExclusion: cluster.policyExclusion } : {}),
    ...(cluster.policyExcludedOccurrenceIds
      ? { policyExcludedOccurrenceIds: cluster.policyExcludedOccurrenceIds }
      : {}),
    secretId: cluster.secretId,
    presence: cluster.presence,
    rootId: cluster.rootId,
    path: cluster.path,
    lineStart: cluster.lineStart,
    lineEnd: cluster.lineEnd,
    category: cluster.category,
    severity: cluster.severity,
    ...(cluster.description === undefined ? {} : { description: cluster.description }),
    ...(raw === undefined ? {} : { raw }),
    ...(match === undefined ? {} : { match }),
    foundBy: cluster.foundBy,
    notFoundBy: cluster.notFoundBy,
    occurrenceIds: cluster.occurrenceIds,
    locations: cluster.locations,
    ...(cluster.candidateFingerprint === undefined
      ? {}
      : { candidateFingerprint: cluster.candidateFingerprint }),
    ...(cluster.evidence === undefined ? {} : { evidence: cluster.evidence }),
    ...(cluster.llm === undefined ? {} : { llm: cluster.llm }),
    effectiveStatus: cluster.effectiveStatus,
    effectiveSeverity: cluster.effectiveSeverity,
    ...(cluster.suppressionReason === undefined
      ? {}
      : { suppressionReason: cluster.suppressionReason }),
  };
}

export function publicManifest(result: ScanResult, includeRaw = false): Record<string, unknown> {
  return {
    schemaVersion: result.schemaVersion,
    outcome: result.outcome,
    exitCode: result.exitCode,
    failOn: result.failOn,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    roots: result.roots.map((root) => ({ rootId: root.rootId, path: root.supplied })),
    detectors: result.detectors,
    ...(result.classifier === undefined ? {} : { classifier: result.classifier }),
    ...(result.llm === undefined ? {} : { llm: result.llm }),
    occurrences: result.occurrences.map(publicOccurrence),
    clusters: result.clusters.map((cluster) => publicCluster(cluster, includeRaw)),
    coverage: result.coverage,
    skipped: result.skipped,
    summary: result.walk,
    errors: result.errors,
  };
}
