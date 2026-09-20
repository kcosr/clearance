import type { AppConfig } from "../config.js";
import { compareSemver, formatSemver, occurrenceId, parseSemver } from "../ids.js";
import type { DetectorResult, Occurrence, RootRecord } from "../types.js";
import { classifyTrufflehogDetector } from "./classify.js";
import { fileExists, historyPathForRoot, postFilterPath, relativizeToRoot } from "./paths.js";
import {
  classifyVersion,
  runCommand,
} from "./process.js";

export const TRUFFLEHOG_MIN = { major: 3, minor: 90, patch: 0 };
export const TRUFFLEHOG_TESTED = { major: 3, minor: 97, patch: 0 };
export const TRUFFLEHOG_FINDINGS_EXIT = 183;

export type AdapterRun = {
  detector: DetectorResult;
  occurrences: Occurrence[];
  warning?: string;
};

type ThFinding = {
  DetectorName?: string;
  /**
   * Fixed per-detector text chosen by TruffleHog, never derived from the
   * matched bytes, so it is safe to publish. Unlike `Raw`/`RawV2`/`SecretParts`/
   * `ExtraData`, which we never read.
   */
  DetectorDescription?: string;
  SourceMetadata?: {
    Data?: {
      Filesystem?: { file?: string; line?: number };
      Git?: { file?: string; line?: number; commit?: string };
    };
  };
};

export async function preflightTrufflehog(
  bin: string,
  warn: (message: string) => void,
  env?: NodeJS.ProcessEnv,
  limits?: AppConfig["limits"],
): Promise<DetectorResult> {
  const result = await runCommand(bin, ["--version"], {
    timeoutMs: limits?.versionTimeoutMs ?? 5_000,
    maxStdoutBytes: 4096,
    ...(env === undefined ? {} : { env }),
  });
  if (result.missing) {
    return { name: "trufflehog", enabled: true, status: "failed", error: "missing-binary" };
  }
  if (result.timedOut || result.exitCode !== 0) {
    return { name: "trufflehog", enabled: true, status: "failed", error: "unsupported-version" };
  }
  const check = classifyVersion(
    `${result.stdout.toString("utf8")} ${result.stderr}`,
    TRUFFLEHOG_MIN,
    TRUFFLEHOG_TESTED,
    "trufflehog",
    parseSemver,
    compareSemver,
    formatSemver,
  );
  if (!check.ok) {
    return { name: "trufflehog", enabled: true, status: "failed", error: check.error };
  }
  if (check.warn) warn(`clearance: warning: ${check.warn}`);
  return { name: "trufflehog", enabled: true, status: "completed", version: check.version };
}

/**
 * Count finding records in a TruffleHog NDJSON stream, before any
 * include/exclude post-filtering. Exit 183 tells us TruffleHog matched
 * something; it says nothing about whether those paths are in scope for us, so
 * the exit-code cross-check has to compare against this rather than against the
 * filtered occurrence list.
 */
export function countTrufflehogFindings(raw: string): number {
  let count = 0;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    let item: ThFinding;
    try {
      item = JSON.parse(trimmed) as ThFinding;
    } catch {
      continue;
    }
    // Version / progress lines are JSON but not findings.
    if (!item.DetectorName && !item.SourceMetadata) continue;
    count += 1;
  }
  return count;
}

export function parseTrufflehogNdjson(
  raw: string,
  options: {
    root: RootRecord;
    history: boolean;
    config: AppConfig;
    extraExclude: string[];
  },
): Occurrence[] {
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length > options.config.limits.maxFindings) {
    throw Object.assign(new Error("finding-limit"), { code: "finding-limit" });
  }
  const occurrences: Occurrence[] = [];
  for (const line of lines) {
    let item: ThFinding;
    try {
      item = JSON.parse(line) as ThFinding;
    } catch {
      throw Object.assign(new Error("unparseable"), { code: "unparseable" });
    }
    // Version / progress lines are JSON but not findings.
    if (!item.DetectorName && !item.SourceMetadata) continue;
    const data = item.SourceMetadata?.Data;
    if (options.history) {
      const git = data?.Git;
      if (!git?.file || !git.commit) {
        throw Object.assign(new Error("unparseable"), { code: "unparseable" });
      }
      if (git.file.includes("!")) {
        throw Object.assign(new Error("archive-member"), { code: "archive-member" });
      }
      const rel = historyPathForRoot(options.root, git.file);
      if (rel === undefined || rel === ".") continue;
      if (!postFilterPath(rel, options.config, options.extraExclude)) continue;
      const lineStart = git.line && git.line > 0 ? git.line : 1;
      const ruleId = item.DetectorName || "trufflehog";
      const classified = classifyTrufflehogDetector(ruleId);
      const source = { kind: "git" as const, commit: git.commit };
      occurrences.push({
        occurrenceId: occurrenceId({
          scanner: "trufflehog",
          rootId: options.root.rootId,
          path: rel,
          lineStart,
          lineEnd: lineStart,
          ruleId,
          source,
        }),
        scanner: "trufflehog",
        rootId: options.root.rootId,
        path: rel,
        lineStart,
        lineEnd: lineStart,
        ruleId,
        category: classified.category,
        severity: classified.severity,
        ...(item.DetectorDescription?.trim() ? { message: item.DetectorDescription.trim() } : {}),
        source,
        extraction: "inexact",
      });
    } else {
      if (data?.Git) {
        throw Object.assign(new Error("unexpected-git-metadata"), { code: "unexpected-git-metadata" });
      }
      const file = data?.Filesystem?.file;
      if (!file) {
        throw Object.assign(new Error("unparseable"), { code: "unparseable" });
      }
      if (file.includes("!")) {
        throw Object.assign(new Error("archive-member"), { code: "archive-member" });
      }
      const rel = relativizeToRoot(file, options.root.realPath);
      if (rel === undefined || rel === ".") continue;
      if (!postFilterPath(rel, options.config, options.extraExclude)) continue;
      const lineStart = data?.Filesystem?.line && data.Filesystem.line > 0 ? data.Filesystem.line : 1;
      const ruleId = item.DetectorName || "trufflehog";
      const classified = classifyTrufflehogDetector(ruleId);
      occurrences.push({
        occurrenceId: occurrenceId({
          scanner: "trufflehog",
          rootId: options.root.rootId,
          path: rel,
          lineStart,
          lineEnd: lineStart,
          ruleId,
          source: { kind: "workingTree" },
        }),
        scanner: "trufflehog",
        rootId: options.root.rootId,
        path: rel,
        lineStart,
        lineEnd: lineStart,
        ruleId,
        category: classified.category,
        severity: classified.severity,
        ...(item.DetectorDescription?.trim() ? { message: item.DetectorDescription.trim() } : {}),
        source: { kind: "workingTree" },
        extraction: "inexact",
      });
    }
  }
  return occurrences;
}

export async function runTrufflehogOnRoot(options: {
  root: RootRecord;
  history: boolean;
  config: AppConfig;
  extraExclude: string[];
  version?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<AdapterRun> {
  const name = options.history ? "trufflehog-history" : "trufflehog";
  const limits = options.config.limits;
  const enabled = options.history
    ? options.config.detectors.trufflehog.history
    : options.config.detectors.trufflehog.enabled;
  const failed = (error: string): AdapterRun => ({
    detector: {
      name,
      enabled,
      status: "failed",
      ...(options.version === undefined ? {} : { version: options.version }),
      error,
    },
    occurrences: [],
  });

  const invokeRoot = options.history
    ? (options.root.git.topLevel ?? options.root.realPath)
    : options.root.realPath;
  const args = options.history
    ? [
        "git",
        `file://${invokeRoot}`,
        "--json",
        "--no-update",
        "--no-verification",
        "--no-color",
        "--results=verified,unverified,unknown,filtered_unverified",
        "--fail",
        "--force-skip-archives",
      ]
    : [
        "filesystem",
        invokeRoot,
        "--json",
        "--no-update",
        "--no-verification",
        "--no-color",
        "--results=unverified,unknown,filtered_unverified",
        "--fail",
        "--force-skip-archives",
      ];
  const cfg = options.config.detectors.trufflehog.config;
  if (cfg) {
    if (!fileExists(cfg)) return failed("missing-admin-config");
    args.push("--config", cfg);
  }
  for (const detector of options.config.detectors.trufflehog.includeDetectors) {
    args.push("--include-detectors", detector);
  }
  for (const detector of options.config.detectors.trufflehog.excludeDetectors) {
    args.push("--exclude-detectors", detector);
  }

  const result = await runCommand(options.config.detectors.trufflehog.bin, args, {
    timeoutMs: limits.scannerTimeoutMs,
    maxStdoutBytes: limits.maxStdoutBytes,
    ...(options.env === undefined ? {} : { env: options.env }),
  });
  if (result.missing) return failed("missing-binary");
  if (result.timedOut) return failed("timeout");
  if (result.truncated) return failed("output-limit");
  if (result.exitCode !== 0 && result.exitCode !== TRUFFLEHOG_FINDINGS_EXIT) {
    return failed("adapter-error");
  }
  const stdout = result.stdout.toString("utf8");
  let occurrences: Occurrence[];
  try {
    occurrences = parseTrufflehogNdjson(stdout, {
      root: options.root,
      history: options.history,
      config: options.config,
      extraExclude: options.extraExclude,
    });
  } catch (error) {
    const code = (error as { code?: string }).code ?? "unparseable";
    return failed(code);
  }
  // Cross-check the exit code against what TruffleHog reported, NOT against what
  // survived our include/exclude post-filter. A secret inside an excluded path
  // (node_modules/** by default) legitimately yields exit 183 and zero
  // occurrences; treating that as an adapter error fails the run on most repos.
  const reported = countTrufflehogFindings(stdout);
  if (result.exitCode === 0 && reported > 0) return failed("adapter-error");
  if (result.exitCode === TRUFFLEHOG_FINDINGS_EXIT && reported === 0) {
    return failed("adapter-error");
  }
  return {
    detector: {
      name,
      enabled,
      status: "completed",
      ...(options.version === undefined ? {} : { version: options.version }),
    },
    occurrences,
  };
}
