import { clusterId, fallbackSecretId } from "./ids.js";
import {
  maxSeverity,
  type Cluster,
  type ClusterLocation,
  type DetectorResult,
  type Occurrence,
  type ScannerName,
} from "./types.js";

/** Scanner-supplied rule text is bounded before it reaches an artifact. */
const DESCRIPTION_MAX_CHARS = 300;

function adjacent(aStart: number, aEnd: number, bStart: number, bEnd: number): boolean {
  return aEnd + 2 >= bStart && bEnd + 2 >= aStart;
}

function commitOf(occ: Occurrence): string | undefined {
  return occ.source.kind === "git" ? occ.source.commit : undefined;
}

function secretKey(occ: Occurrence): string {
  if (occ.extraction === "exact" && occ.candidateFingerprint) return `H:${occ.candidateFingerprint}`;
  const commit = commitOf(occ);
  return fallbackSecretId({
    scanner: occ.scanner,
    ruleId: occ.ruleId,
    path: occ.path,
    lineStart: occ.lineStart,
    ...(commit ? { commit } : {}),
  });
}

function sameSourceLocation(a: Occurrence, b: Occurrence): boolean {
  if (a.source.kind !== b.source.kind) return false;
  if (a.source.kind === "git" && b.source.kind === "git") {
    return a.source.commit === b.source.commit;
  }
  return true;
}

function overlaps(a: Occurrence, b: Occurrence): boolean {
  return a.lineStart <= b.lineEnd && b.lineStart <= a.lineEnd;
}

function sourceLocationKey(occ: Occurrence): string {
  const commit = occ.source.kind === "git" ? occ.source.commit : "";
  return `${occ.rootId}\0${occ.path}\0${occ.category}\0${occ.source.kind}\0${commit}`;
}

/**
 * An inexact occurrence has no cross-scanner identity of its own. It may still
 * join one unambiguous exact finding at the same source location: same root,
 * path, category, overlapping range, and (for history) commit. If two distinct
 * exact candidates overlap, keep the inexact hit separate rather than guess.
 */
function correlationKey(occ: Occurrence, exactByLocation: Map<string, Occurrence[]>): string {
  const own = secretKey(occ);
  if (occ.extraction !== "inexact") return own;

  const candidates = new Set(
    (exactByLocation.get(sourceLocationKey(occ)) ?? [])
      .filter(
        (other) =>
          other.candidateFingerprint !== undefined &&
          sameSourceLocation(occ, other) &&
          overlaps(occ, other),
      )
      .map((other) => secretKey(other)),
  );
  return candidates.size === 1 ? [...candidates][0]! : own;
}

function completedScanners(
  detectors: DetectorResult[],
  historical: boolean,
): ScannerName[] {
  const names = new Set<ScannerName>();
  for (const detector of detectors) {
    if (detector.status !== "completed") continue;
    if (historical) {
      if (detector.name === "gitleaks-history") names.add("gitleaks");
      if (detector.name === "trufflehog-history") names.add("trufflehog");
    } else {
      if (detector.name === "native") names.add("native");
      if (detector.name === "gitleaks") names.add("gitleaks");
      if (detector.name === "trufflehog") names.add("trufflehog");
    }
  }
  return [...names];
}

function mergeLocations(occurrences: Occurrence[]): ClusterLocation[] {
  const map = new Map<string, ClusterLocation>();
  for (const occ of occurrences) {
    const commit = commitOf(occ);
    const key = `${occ.path}\0${commit ?? ""}\0${occ.lineStart}`;
    const existing = map.get(key);
    if (existing) {
      if (!existing.scanners.includes(occ.scanner)) existing.scanners.push(occ.scanner);
    } else {
      map.set(key, {
        path: occ.path,
        ...(commit === undefined ? {} : { commit }),
        lineStart: occ.lineStart,
        scanners: [occ.scanner],
      });
    }
  }
  return [...map.values()].sort((a, b) =>
    a.path.localeCompare(b.path) ||
    (a.commit ?? "").localeCompare(b.commit ?? "") ||
    a.lineStart - b.lineStart,
  );
}

function pickPrimary(occurrences: Occurrence[]): Occurrence {
  const wt = occurrences.filter((occ) => occ.source.kind === "workingTree");
  const pool = wt.length > 0 ? wt : occurrences;
  return [...pool].sort(
    (a, b) => a.path.localeCompare(b.path) || a.lineStart - b.lineStart || a.scanner.localeCompare(b.scanner),
  )[0]!;
}

function buildCluster(
  id: string,
  secretId: string,
  members: Occurrence[],
  detectors: DetectorResult[],
): Cluster {
  const historical = members.some((occ) => occ.source.kind === "git");
  const current = members.some((occ) => occ.source.kind === "workingTree");
  const presence = current && historical ? "current_and_historical" : historical ? "historical" : "current";
  const primary = pickPrimary(members);
  const completed = completedScanners(detectors, !current && historical);
  const foundBy = [...new Set(members.map((occ) => occ.scanner))].sort();
  const notFoundBy = completed.filter((name) => !foundBy.includes(name));
  const fingerprint = members.find((occ) => occ.candidateFingerprint)?.candidateFingerprint;
  // Rule/detector text, deterministic across runs: first non-empty message in
  // occurrenceId order. Truncated because the string comes from the tool, not us.
  const description = [...members]
    .sort((a, b) => a.occurrenceId.localeCompare(b.occurrenceId))
    .map((occ) => occ.message?.trim())
    .find((text): text is string => text !== undefined && text.length > 0)
    ?.slice(0, DESCRIPTION_MAX_CHARS);
  // Carried so the report layer can publish it under [report].includeRaw. Only
  // an `exact` extraction is trustworthy as "the secret" rather than context.
  const candidate = members.find((occ) => occ.extraction === "exact" && occ.candidate)?.candidate;
  // Prefer a working-tree line: it is the one an operator can go and look at.
  const match =
    members.find((occ) => occ.source.kind === "workingTree" && occ.matchLine)?.matchLine ??
    members.find((occ) => occ.matchLine)?.matchLine;
  const evidence = members.every((occ) => occ.extraction === "exact")
    ? "exact"
    : members.some((occ) => occ.extraction === "unavailable") &&
        !members.some((occ) => occ.extraction === "exact")
      ? "unavailable"
      : "inexact";
  return {
    clusterId: id,
    secretId,
    presence,
    rootId: primary.rootId,
    path: primary.path,
    lineStart: primary.lineStart,
    lineEnd: primary.lineEnd,
    category: primary.category,
    severity: maxSeverity(members.map((occ) => occ.severity)),
    ...(description === undefined ? {} : { description }),
    foundBy,
    notFoundBy,
    occurrenceIds: members.map((occ) => occ.occurrenceId).sort(),
    locations: mergeLocations(members),
    ...(fingerprint === undefined ? {} : { candidateFingerprint: fingerprint }),
    ...(candidate === undefined ? {} : { candidate }),
    ...(match === undefined ? {} : { match }),
    evidence,
    effectiveStatus: "open",
    effectiveSeverity: maxSeverity(members.map((occ) => occ.severity)),
  };
}

export function clusterOccurrences(occurrences: Occurrence[], detectors: DetectorResult[]): Cluster[] {
  const exactByLocation = new Map<string, Occurrence[]>();
  for (const occ of occurrences) {
    if (occ.extraction !== "exact" || !occ.candidateFingerprint) continue;
    const key = sourceLocationKey(occ);
    const list = exactByLocation.get(key) ?? [];
    list.push(occ);
    exactByLocation.set(key, list);
  }

  const byRootSecret = new Map<string, Occurrence[]>();
  for (const occ of occurrences) {
    const key = `${occ.rootId}\0${correlationKey(occ, exactByLocation)}`;
    const list = byRootSecret.get(key) ?? [];
    list.push(occ);
    byRootSecret.set(key, list);
  }

  const raw: Cluster[] = [];
  for (const [key, group] of byRootSecret) {
    const secretId = key.slice(key.indexOf("\0") + 1);
    const working = group.filter((occ) => occ.source.kind === "workingTree");
    const history = group.filter((occ) => occ.source.kind === "git");

    const wtGroups: { members: Occurrence[]; lineStart: number; lineEnd: number }[] = [];
    for (const occ of [...working].sort((a, b) => a.path.localeCompare(b.path) || a.lineStart - b.lineStart)) {
      const existing = wtGroups.find(
        (group) =>
          group.members[0]!.path === occ.path &&
          adjacent(group.lineStart, group.lineEnd, occ.lineStart, occ.lineEnd),
      );
      if (existing) {
        existing.members.push(occ);
        existing.lineStart = Math.min(existing.lineStart, occ.lineStart);
        existing.lineEnd = Math.max(existing.lineEnd, occ.lineEnd);
      } else {
        wtGroups.push({ members: [occ], lineStart: occ.lineStart, lineEnd: occ.lineEnd });
      }
    }

    if (wtGroups.length === 0 && history.length > 0) {
      raw.push(buildCluster("pending", secretId, history, detectors));
      continue;
    }
    for (const group of wtGroups) {
      const combined = history.length > 0 ? [...group.members, ...history] : group.members;
      raw.push(buildCluster("pending", secretId, combined, detectors));
    }
  }

  raw.sort(
    (a, b) =>
      a.rootId.localeCompare(b.rootId) ||
      a.path.localeCompare(b.path) ||
      a.lineStart - b.lineStart ||
      a.secretId.localeCompare(b.secretId),
  );
  return raw.map((cluster, index) => ({ ...cluster, clusterId: clusterId(index + 1) }));
}
