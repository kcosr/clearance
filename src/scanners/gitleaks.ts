import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AppConfig } from "../config.js";
import { compareSemver, formatSemver, occurrenceId, parseSemver } from "../ids.js";
import { readPackagedPolicy } from "../packaged-policy.js";
import type { DetectorResult, Occurrence, RootRecord } from "../types.js";
import { classifyGitleaksRule, isRedactedSecret } from "./classify.js";
import { fileExists, historyPathForRoot, megabytesFromMaxBytes, postFilterPath, relativizeToRoot } from "./paths.js";
import {
  classifyVersion,
  runCommand,
} from "./process.js";

export const GITLEAKS_MIN = { major: 8, minor: 19, patch: 0 };
export const GITLEAKS_TESTED = { major: 8, minor: 30, patch: 1 };

export type GitleaksFinding = {
  RuleID?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Secret?: string;
  File?: string;
  Commit?: string;
  Fingerprint?: string;
};

export type AdapterRun = {
  detector: DetectorResult;
  occurrences: Occurrence[];
  warning?: string;
};

export async function preflightGitleaks(
  bin: string,
  warn: (message: string) => void,
  env?: NodeJS.ProcessEnv,
  limits?: AppConfig["limits"],
): Promise<DetectorResult> {
  const result = await runCommand(bin, ["version"], {
    timeoutMs: limits?.versionTimeoutMs ?? 5_000,
    maxStdoutBytes: 4096,
    ...(env === undefined ? {} : { env }),
  });
  if (result.missing) {
    return { name: "gitleaks", enabled: true, status: "failed", error: "missing-binary" };
  }
  if (result.timedOut || result.exitCode !== 0) {
    return { name: "gitleaks", enabled: true, status: "failed", error: "unsupported-version" };
  }
  const check = classifyVersion(
    result.stdout.toString("utf8"),
    GITLEAKS_MIN,
    GITLEAKS_TESTED,
    "gitleaks",
    parseSemver,
    compareSemver,
    formatSemver,
  );
  if (!check.ok) {
    return { name: "gitleaks", enabled: true, status: "failed", error: check.error };
  }
  if (check.warn) warn(`clearance: warning: ${check.warn}`);
  return { name: "gitleaks", enabled: true, status: "completed", version: check.version };
}

export function parseGitleaksReport(
  raw: string,
  options: {
    root: RootRecord;
    history: boolean;
    config: AppConfig;
    extraExclude: string[];
  },
): Occurrence[] {
  const parsed = JSON.parse(raw) as unknown;
  if (!Array.isArray(parsed)) {
    throw Object.assign(new Error("unparseable gitleaks report"), { code: "unparseable" });
  }
  if (parsed.length > options.config.limits.maxFindings) {
    throw Object.assign(new Error("finding-limit"), { code: "finding-limit" });
  }
  const occurrences: Occurrence[] = [];
  for (const item of parsed as GitleaksFinding[]) {
    if (typeof item.File !== "string" || !item.File) {
      throw Object.assign(new Error("malformed gitleaks finding"), { code: "unparseable" });
    }
    if (item.File.includes("!")) {
      throw Object.assign(new Error("archive-member"), { code: "archive-member" });
    }
    if (!isRedactedSecret(item.Secret)) {
      throw Object.assign(new Error("unredacted-secret"), { code: "unredacted-secret" });
    }
    const commit = item.Commit?.trim() ?? "";
    if (!options.history && commit) {
      throw Object.assign(new Error("unexpected-git-metadata"), { code: "unexpected-git-metadata" });
    }
    if (options.history && !commit) {
      throw Object.assign(new Error("missing-commit"), { code: "unparseable" });
    }
    const rel = options.history
      ? historyPathForRoot(options.root, item.File)
      : relativizeToRoot(item.File, options.root.realPath);
    if (rel === undefined || rel === ".") continue;
    if (!postFilterPath(rel, options.config, options.extraExclude)) continue;
    const lineStart = item.StartLine && item.StartLine > 0 ? item.StartLine : 1;
    const lineEnd = item.EndLine && item.EndLine > 0 ? item.EndLine : lineStart;
    const ruleId = item.RuleID || "gitleaks";
    const classified = classifyGitleaksRule(ruleId);
    const source = options.history ? ({ kind: "git" as const, commit }) : { kind: "workingTree" as const };
    const columnStart = item.StartColumn && item.StartColumn > 0 ? item.StartColumn : undefined;
    const columnEnd = item.EndColumn && item.EndColumn > 0 ? item.EndColumn : undefined;
    occurrences.push({
      occurrenceId: occurrenceId({
        scanner: "gitleaks",
        rootId: options.root.rootId,
        path: rel,
        lineStart,
        lineEnd,
        ...(columnStart === undefined ? {} : { columnStart }),
        ...(columnEnd === undefined ? {} : { columnEnd }),
        ruleId,
        source,
      }),
      scanner: "gitleaks",
      rootId: options.root.rootId,
      path: rel,
      lineStart,
      lineEnd,
      ...(columnStart === undefined ? {} : { columnStart }),
      ...(columnEnd === undefined ? {} : { columnEnd }),
      ruleId,
      category: classified.category,
      severity: classified.severity,
      ...(item.Description ? { message: item.Description } : {}),
      source,
      extraction: "inexact",
    });
  }
  return occurrences;
}

export async function runGitleaksOnRoot(options: {
  root: RootRecord;
  history: boolean;
  config: AppConfig;
  extraExclude: string[];
  version?: string;
  warn: (message: string) => void;
  env?: NodeJS.ProcessEnv;
}): Promise<AdapterRun> {
  const name = options.history ? "gitleaks-history" : "gitleaks";
  const limits = options.config.limits;
  const enabled = options.history
    ? options.config.detectors.gitleaks.history
    : options.config.detectors.gitleaks.enabled;
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

  const cfg = options.config.detectors.gitleaks.config;
  const ignore = options.config.detectors.gitleaks.ignore;
  const packagedConfig = readPackagedPolicy(cfg);
  const packagedIgnore = readPackagedPolicy(ignore);
  if (
    !cfg ||
    !ignore ||
    (packagedConfig === undefined && !fileExists(cfg)) ||
    (packagedIgnore === undefined && !fileExists(ignore))
  ) {
    return failed("missing-admin-config");
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-gitleaks-"));
  const reportPath = path.join(tmp, options.history ? "gitleaks-git.json" : "gitleaks.json");
  const scannerConfigPath = path.join(tmp, "gitleaks.toml");
  const scannerIgnorePath = path.join(tmp, "gitleaks.ignore");
  try {
    // The standalone build embeds policy text, but the external Gitleaks
    // process requires real paths. Materialize every policy in a private
    // directory so source installs and executables use the same immutable
    // snapshot for the duration of the scan.
    fs.writeFileSync(scannerConfigPath, packagedConfig ?? fs.readFileSync(cfg, "utf8"), {
      mode: 0o600,
    });
    fs.writeFileSync(scannerIgnorePath, packagedIgnore ?? fs.readFileSync(ignore, "utf8"), {
      mode: 0o600,
    });
  } catch {
    fs.rmSync(tmp, { recursive: true, force: true });
    return failed("missing-admin-config");
  }
  const invokeRoot = options.history
    ? (options.root.git.topLevel ?? options.root.realPath)
    : options.root.realPath;
  const args = [
    options.history ? "git" : "dir",
    invokeRoot,
    "--no-banner",
    "--no-color",
    "--log-level",
    "error",
    "--report-format",
    "json",
    "--report-path",
    reportPath,
    "--redact=100",
    "--exit-code",
    "1",
    "--config",
    scannerConfigPath,
    "--gitleaks-ignore-path",
    scannerIgnorePath,
    "--max-archive-depth",
    "0",
  ];
  const mb = megabytesFromMaxBytes(options.config.scan.maxFileBytes);
  if (mb !== undefined) {
    args.push("--max-target-megabytes", String(mb));
  }

  const result = await runCommand(options.config.detectors.gitleaks.bin, args, {
    timeoutMs: limits.scannerTimeoutMs,
    maxStdoutBytes: limits.maxStdoutBytes,
    ...(options.env === undefined ? {} : { env: options.env }),
  });
  try {
    if (result.missing) return failed("missing-binary");
    if (result.timedOut) return failed("timeout");
    if (result.truncated) return failed("output-limit");
    if (!fs.existsSync(reportPath)) {
      if (result.exitCode !== 0 && result.exitCode !== 1) return failed("adapter-error");
      return failed("unparseable");
    }
    const stat = fs.statSync(reportPath);
    if (stat.size > limits.maxReportBytes) return failed("output-limit");
    const raw = fs.readFileSync(reportPath, "utf8");
    let occurrences: Occurrence[];
    try {
      occurrences = parseGitleaksReport(raw || "[]", {
        root: options.root,
        history: options.history,
        config: options.config,
        extraExclude: options.extraExclude,
      });
    } catch (error) {
      const code = (error as { code?: string }).code ?? "unparseable";
      return failed(code);
    }
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      if (occurrences.length > 0) {
        options.warn("clearance: warning: gitleaks exit did not match report; accepting report");
      } else {
        return failed("adapter-error");
      }
    } else if ((result.exitCode === 1) !== occurrences.length > 0 && raw.trim() && raw.trim() !== "[]") {
      options.warn("clearance: warning: gitleaks exit did not match report; accepting report");
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
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
