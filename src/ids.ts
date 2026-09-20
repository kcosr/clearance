import { createHash, createHmac, randomBytes } from "node:crypto";
import type { OccurrenceSource } from "./types.js";

export function newRunKey(): Buffer {
  return randomBytes(32);
}

export function occurrenceId(fields: {
  scanner: string;
  rootId: string;
  path: string;
  lineStart: number;
  lineEnd: number;
  columnStart?: number;
  columnEnd?: number;
  ruleId: string;
  source: OccurrenceSource;
}): string {
  const canonical = JSON.stringify({
    scanner: fields.scanner,
    rootId: fields.rootId,
    path: fields.path,
    lineStart: fields.lineStart,
    lineEnd: fields.lineEnd,
    columnStart: fields.columnStart ?? null,
    columnEnd: fields.columnEnd ?? null,
    ruleId: fields.ruleId,
    source: fields.source,
  });
  return `O-${createHash("sha256").update(canonical).digest("hex").slice(0, 16)}`;
}

export function candidateFingerprint(runKey: Buffer, candidate: string): string {
  return createHmac("sha256", runKey).update(candidate, "utf8").digest("hex");
}

export function fallbackSecretId(fields: {
  scanner: string;
  ruleId: string;
  path: string;
  lineStart: number;
  commit?: string;
}): string {
  const parts = [fields.scanner, fields.ruleId, fields.path, String(fields.lineStart)];
  if (fields.commit) parts.push(fields.commit);
  return `F-${createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 16)}`;
}

export function clusterId(index: number): string {
  return `C-${String(index).padStart(6, "0")}`;
}

export function batchId(index: number): string {
  return `B-${String(index).padStart(4, "0")}`;
}

export type Semver = { major: number; minor: number; patch: number };

export function parseSemver(text: string): Semver | undefined {
  const match = text.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return undefined;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

export function compareSemver(a: Semver, b: Semver): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

export function formatSemver(v: Semver): string {
  return `${v.major}.${v.minor}.${v.patch}`;
}
