import fs from "node:fs";
import { applyTestFixturePolicy } from "./test-fixtures.js";
import { progressSink } from "./progress.js";
import { findingMessage, verdictMessage } from "./live-findings.js";
import { createHash } from "node:crypto";
import { captureSnapshots, scanClassifier, verifySnapshots } from "./classifier/scanner.js";
import path from "node:path";
import { parseArgs, HELP_TEXT } from "./cli-parse.js";
import {
  anyDetectorEnabled,
  loadConfig,
  resolveConfigFiles,
  PACKAGE_VERSION,
  type AppConfig,
  type CliOverrides,
} from "./config.js";
import { clusterOccurrences } from "./cluster.js";
import { extractEvidence } from "./evidence.js";
import { newRunKey } from "./ids.js";
import { createAgentsRuntime } from "./llm/agents.js";
import { loadInstructions, type ValidatorRuntime } from "./llm/runtime.js";
import { runValidation } from "./llm/validate.js";
import { loadNativeRules } from "./native/rules.js";
import { runNativeRules } from "./native/scan.js";
import { decideOutcome } from "./outcome.js";
import { isPackagedPolicyPath } from "./packaged-policy.js";
import { formatHumanSummary, writeArtifacts } from "./report/write.js";
import { publicManifest } from "./report/public.js";
import { preflightGitleaks, runGitleaksOnRoot } from "./scanners/gitleaks.js";
import { preflightTrufflehog, runTrufflehogOnRoot } from "./scanners/trufflehog.js";
import { applySuppressions } from "./suppress.js";
import type {
  DetectorName,
  DetectorResult,
  Occurrence,
  RootRecord,
  ScanResult,
  WalkSummary,
} from "./types.js";
import { detectDrift, outputExcludeGlobs, resolveRoots, walkRoots } from "./walk.js";

export type RunOptions = {
  signal?: AbortSignal;
  argv?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdout?: { write(chunk: string): void };
  stderr?: { write(chunk: string): void };
  llmRuntime?: ValidatorRuntime;
  now?: () => Date;
};

const EMPTY_WALK: WalkSummary = {
  walked: 0,
  scannable: 0,
  skippedHarmless: 0,
  excludedByConfig: 0,
  archive: 0,
  oversize: 0,
  unreadable: 0,
};

function writeLine(stream: { write(chunk: string): void } | undefined, text: string): void {
  stream?.write(text.endsWith("\n") ? text : `${text}\n`);
}

function emptyResult(
  partial: Partial<ScanResult> & Pick<ScanResult, "outcome" | "exitCode">,
): ScanResult {
  return {
    schemaVersion: "clearance.report/v1",
    failOn: "high",
    startedAt: new Date(0).toISOString(),
    finishedAt: new Date(0).toISOString(),
    roots: [],
    detectors: [],
    occurrences: [],
    clusters: [],
    coverage: [],
    skipped: [],
    walk: EMPTY_WALK,
    errors: [],
    artifacts: null,
    ...partial,
  };
}

function skippedDetector(name: DetectorName, enabled: boolean, error?: string): DetectorResult {
  return {
    name,
    enabled,
    status: "skipped",
    ...(error === undefined ? {} : { error }),
  };
}

export async function runClearance(options: RunOptions = {}): Promise<ScanResult> {
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;
  const now = options.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const warn = (message: string): void => writeLine(stderr, message);

  let cli: CliOverrides;
  try {
    cli = parseArgs(options.argv ?? process.argv.slice(2));
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid arguments";
    writeLine(stderr, `clearance: error: ${message}`);
    return emptyResult({
      outcome: "error",
      exitCode: 3,
      startedAt,
      finishedAt: now().toISOString(),
      errors: [message],
      failOn: "high",
    });
  }

  if (cli.help) {
    writeLine(stdout, HELP_TEXT);
    return emptyResult({
      outcome: "clean",
      exitCode: 0,
      startedAt,
      finishedAt: now().toISOString(),
    });
  }
  if (cli.version) {
    writeLine(stdout, `clearance ${PACKAGE_VERSION}`);
    return emptyResult({
      outcome: "clean",
      exitCode: 0,
      startedAt,
      finishedAt: now().toISOString(),
    });
  }

  let config: AppConfig;
  try {
    config = loadConfig(cli, env);
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid config";
    writeLine(stderr, `clearance: error: ${message}`);
    return finish(
      emptyResult({
        outcome: "error",
        exitCode: 3,
        startedAt,
        finishedAt: now().toISOString(),
        errors: [message],
        failOn: "high",
      }),
      cwd,
      cli.outputDir ?? env.CLEARANCE_OUTPUT ?? "./clearance-report",
      cli,
      stdout,
      cli.json === true,
      { enabled: false, includeRaw: false },
    );
  }

  const showProgress =
    config.report.progress === "on" ||
    (config.report.progress === "auto" &&
      cli.json !== true &&
      "isTTY" in stderr &&
      stderr.isTTY === true);
  const progress = progressSink(showProgress, stderr);
  progress("pipeline: preparing inventory");

  if (config.llm.traceFile && !path.isAbsolute(config.llm.traceFile)) {
    config.llm.traceFile = path.resolve(cwd, config.report.outputDir, config.llm.traceFile);
  }

  if (!anyDetectorEnabled(config)) {
    const message = "every detector is disabled";
    writeLine(stderr, `clearance: error: ${message}`);
    return finish(
      emptyResult({
        outcome: "error",
        exitCode: 3,
        startedAt,
        finishedAt: now().toISOString(),
        errors: [message],
        failOn: config.report.failOn,
      }),
      cwd,
      config.report.outputDir,
      cli,
      stdout,
      cli.json === true,
      config.report,
    );
  }

  const supplied = cli.roots.length > 0 ? cli.roots : [cwd];
  let roots;
  try {
    roots = resolveRoots(supplied);
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid roots";
    writeLine(stderr, `clearance: error: ${message}`);
    return finish(
      emptyResult({
        outcome: "error",
        exitCode: 3,
        startedAt,
        finishedAt: now().toISOString(),
        errors: [message],
        failOn: config.report.failOn,
      }),
      cwd,
      config.report.outputDir,
      cli,
      stdout,
      cli.json === true,
      config.report,
    );
  }

  // Admin policy must not come from the tree being scanned: a repo that can
  // drop in its own rules, gitleaks config, ignore file, or validator prompt can
  // clear itself. The scanner flags already pin admin paths explicitly; this
  // catches an operator pointing them at something inside a scan root.
  const insidePolicy =
    adminPolicyInsideRoots(config, roots, cwd) ??
    (config.detectors.classifier.enabled &&
    resolveConfigFiles(cli.configPath, env).some((file) => pathInsideRoots(file.path, roots, cwd))
      ? "classifier configuration"
      : undefined);
  if (insidePolicy) {
    const message = `admin policy inside a scan root: ${insidePolicy}`;
    writeLine(stderr, `clearance: error: ${message}`);
    return finish(
      emptyResult({
        outcome: "error",
        exitCode: 3,
        startedAt,
        finishedAt: now().toISOString(),
        errors: [message],
        failOn: config.report.failOn,
      }),
      cwd,
      config.report.outputDir,
      cli,
      stdout,
      cli.json === true,
      config.report,
    );
  }

  // Reserve output paths only when something will actually write there. An
  // unused --output must not silently exclude source files in no-report mode.
  const outputDir = path.resolve(cwd, config.report.outputDir);
  const tracePath = config.llm.traceFile ? path.resolve(config.llm.traceFile) : undefined;
  const traceInOutput =
    config.llm.enabled &&
    tracePath !== undefined &&
    (tracePath === outputDir || tracePath.startsWith(path.join(outputDir, path.sep)));
  const reserveOutput = config.report.enabled || traceInOutput;
  let outputRealPath: string | undefined;
  try {
    if (reserveOutput && fs.existsSync(outputDir)) outputRealPath = fs.realpathSync(outputDir);
  } catch {
    outputRealPath = undefined;
  }
  const extraExclude = reserveOutput ? outputExcludeGlobs(config.report.outputDir, cwd) : [];
  const firstWalk = walkRoots(roots, config, {
    extraExclude,
    ...(outputRealPath ? { outputRealPath } : {}),
  });

  const detectors: DetectorResult[] = [];
  const occurrences: Occurrence[] = [];
  const errors: string[] = [];
  const runKey = newRunKey();
  const rootById = new Map(roots.map((root) => [root.rootId, root]));
  // Commit-addressed evidence is immutable. Reuse successful previews so live
  // history output does not spawn a second git show for every occurrence.
  const historyEvidence = new WeakMap<Occurrence, Occurrence>();
  const onFinding = (occ: Occurrence): void => {
    if (!showProgress) return;
    // Preview evidence for external scanners without changing the evidence used
    // later by correlation/validation. Presentation must never fail a detector.
    try {
      const root = rootById.get(occ.rootId);
      const preview =
        root && !occ.candidate && occ.matchKind !== "filename"
          ? extractEvidence(occ, root, config, runKey)
          : occ;
      if (preview !== occ && occ.source.kind === "git" && preview.extraction !== "unavailable") {
        historyEvidence.set(occ, preview);
      }
      progress(findingMessage(preview));
    } catch {
      progress(findingMessage(occ));
    }
  };
  const snapshots = config.detectors.classifier.enabled
    ? captureSnapshots(firstWalk.files, roots, config.detectors.classifier)
    : new Map();

  progress("pipeline: native rules");
  if (config.detectors.native.enabled) {
    try {
      const rules = loadNativeRules(config.detectors.native.rulesD);
      const nativeHits = runNativeRules(firstWalk.files, rules, onFinding);
      occurrences.push(...nativeHits);
      detectors.push({ name: "native", enabled: true, status: "completed" });
    } catch (error) {
      const message = error instanceof Error ? error.message : "native-failed";
      errors.push(message);
      detectors.push({ name: "native", enabled: true, status: "failed", error: "adapter-error" });
    }
  } else {
    detectors.push(skippedDetector("native", false));
  }

  let gitleaksVersion: string | undefined;
  progress("pipeline: Gitleaks current/history scanning");
  if (config.detectors.gitleaks.enabled || config.detectors.gitleaks.history) {
    const pre = await preflightGitleaks(config.detectors.gitleaks.bin, warn, env, config.limits);
    if (pre.status === "failed") {
      if (config.detectors.gitleaks.enabled) {
        detectors.push({ ...pre, name: "gitleaks", enabled: true });
      } else {
        detectors.push(skippedDetector("gitleaks", false));
      }
      if (config.detectors.gitleaks.history) {
        detectors.push({ ...pre, name: "gitleaks-history", enabled: true });
      } else {
        detectors.push(skippedDetector("gitleaks-history", false));
      }
    } else {
      gitleaksVersion = pre.version;
      await runGitleaksDetectors({
        roots,
        config,
        extraExclude,
        ...(gitleaksVersion === undefined ? {} : { version: gitleaksVersion }),
        warn,
        detectors,
        occurrences,
        onFinding,
        env,
      });
    }
  } else {
    detectors.push(skippedDetector("gitleaks", false));
    detectors.push(skippedDetector("gitleaks-history", false));
  }

  progress("pipeline: TruffleHog current/history scanning");
  if (config.detectors.trufflehog.enabled || config.detectors.trufflehog.history) {
    const pre = await preflightTrufflehog(
      config.detectors.trufflehog.bin,
      warn,
      env,
      config.limits,
    );
    if (pre.status === "failed") {
      if (config.detectors.trufflehog.enabled) {
        detectors.push({ ...pre, name: "trufflehog", enabled: true });
      } else {
        detectors.push(skippedDetector("trufflehog", false));
      }
      if (config.detectors.trufflehog.history) {
        detectors.push({ ...pre, name: "trufflehog-history", enabled: true });
      } else {
        detectors.push(skippedDetector("trufflehog-history", false));
      }
    } else {
      await runTrufflehogDetectors({
        roots,
        config,
        extraExclude,
        ...(pre.version === undefined ? {} : { version: pre.version }),
        detectors,
        occurrences,
        onFinding,
        env,
      });
    }
  } else {
    detectors.push(skippedDetector("trufflehog", false));
    detectors.push(skippedDetector("trufflehog-history", false));
  }

  const coverage = [...firstWalk.coverage];
  const secondWalk = walkRoots(roots, config, {
    extraExclude,
    ...(outputRealPath ? { outputRealPath } : {}),
  });
  if (detectDrift(firstWalk.files, secondWalk.files)) {
    coverage.push({ rootId: roots[0]?.rootId ?? "root-1", path: ".", reason: "drift" });
  }

  progress("pipeline: extracting evidence");
  const withEvidence = occurrences.map((occ) => {
    const cached = historyEvidence.get(occ);
    if (cached) return cached;
    // Re-read working files here: unlike commit-addressed blobs, they may have
    // changed since the preview. Failed previews also retain the normal retry.
    const root = rootById.get(occ.rootId);
    if (!root) return { ...occ, extraction: "unavailable" as const };
    return extractEvidence(occ, root, config, runKey);
  });

  let classifierStatus: ScanResult["classifier"];
  if (config.detectors.classifier.enabled) {
    progress("pipeline: external classifier discovery");
    const classified = await scanClassifier({
      progress,
      onFinding,
      config: config.detectors.classifier,
      files: firstWalk.files,
      roots,
      snapshots,
      runKey,
      env,
      ...(options.signal ? { signal: options.signal } : {}),
      maxTotalFindings: Math.max(0, config.limits.maxFindings - withEvidence.length),
    });
    detectors.push(classified.detector);
    withEvidence.push(
      ...classified.occurrences.sort((a, b) => a.occurrenceId.localeCompare(b.occurrenceId)),
    );
    classifierStatus = {
      policyDigest: `sha256:${createHash("sha256").update(JSON.stringify(config.detectors.classifier.policy)).digest("hex")}`,
      files: [
        ...classified.coverage,
        ...firstWalk.skipped
          .filter(
            (s) => !classified.coverage.some((c) => c.rootId === s.rootId && c.path === s.path),
          )
          .map((s) => ({
            rootId: s.rootId,
            path: s.path,
            status: "excluded" as const,
            reason: s.reason,
          })),
      ],
    };
  } else {
    detectors.push(skippedDetector("classifier", false));
  }

  progress("pipeline: correlating findings and applying suppressions");
  let clusters = clusterOccurrences(withEvidence, detectors);
  const suppressed = applySuppressions(withEvidence, clusters, config);
  clusters = suppressed.clusters;

  const detectorFailed = detectors.some(
    (detector) => detector.enabled && detector.status === "failed",
  );
  let llmFailed = false;
  let llmStatus: ScanResult["llm"];
  if (config.llm.enabled && !detectorFailed && errors.length === 0) {
    let streamedVerdicts = 0;
    try {
      progress("pipeline: LLM finding validation");
      const instructions = loadInstructions(config);
      const runtime = options.llmRuntime ?? createAgentsRuntime(config);
      const validated = await runValidation({
        clusters,
        occurrences: suppressed.occurrences,
        config,
        runtime,
        instructions,
        onWarning: warn,
        progress,
        onVerdict: (cluster, verdict) => {
          streamedVerdicts += 1;
          if (showProgress) progress(verdictMessage(cluster, verdict, config.llm.canOverride));
        },
        roots,
      });
      clusters = validated.clusters;
      llmFailed = validated.failed;
      llmStatus = {
        enabled: true,
        mode: "validate",
        model: config.model.model,
        api: config.model.api,
        status: validated.status,
      };
    } catch (error) {
      progress(
        streamedVerdicts > 0
          ? `LLM validation: aborted; discarded streamed verdicts: ${streamedVerdicts}`
          : "LLM validation: aborted before any verdict",
      );
      const message = error instanceof Error ? error.message : "llm-failed";
      errors.push(message);
      llmFailed = config.llm.failurePolicy === "fail";
      llmStatus = {
        enabled: true,
        mode: "validate",
        model: config.model.model,
        api: config.model.api,
        status: "failed",
      };
    }
  }

  progress("pipeline: verifying final coverage");
  if (classifierStatus) {
    verifySnapshots(
      firstWalk.files,
      roots,
      snapshots,
      config.detectors.classifier,
      classifierStatus.files,
    );
    const finalWalk = walkRoots(roots, config, {
      extraExclude,
      ...(outputRealPath ? { outputRealPath } : {}),
    });
    if (detectDrift(firstWalk.files, finalWalk.files))
      coverage.push({ rootId: roots[0]!.rootId, path: ".", reason: "drift" });
    for (const row of classifierStatus.files.filter((c) => c.status === "failed")) {
      coverage.push({ rootId: row.rootId, path: row.path, reason: "classifier-incomplete" });
    }
    if (classifierStatus.files.some((c) => c.status === "failed")) {
      const detector = detectors.find((d) => d.name === "classifier")!;
      if (detector.status !== "failed") {
        detector.status = "partial";
        detector.error = "classification-incomplete";
      }
    }
  }

  const fixturePolicy = applyTestFixturePolicy(suppressed.occurrences, clusters, config);
  clusters = fixturePolicy.clusters;
  const decided = decideOutcome({
    clusters,
    coverage,
    detectors,
    errors,
    failOn: config.report.failOn,
    llmFailed,
  });

  progress(config.report.enabled ? "pipeline: writing reports" : "pipeline: preparing result");
  const result: ScanResult = {
    schemaVersion: "clearance.report/v1",
    outcome: decided.outcome,
    exitCode: decided.exitCode,
    failOn: config.report.failOn,
    startedAt,
    finishedAt: now().toISOString(),
    roots,
    detectors,
    ...(llmStatus === undefined ? {} : { llm: llmStatus }),
    ...(classifierStatus === undefined ? {} : { classifier: classifierStatus }),
    occurrences: fixturePolicy.occurrences,
    clusters,
    coverage,
    skipped: firstWalk.skipped,
    walk: firstWalk.walk,
    errors,
    artifacts: null,
  };
  return finish(
    result,
    cwd,
    config.report.outputDir,
    cli,
    stdout,
    cli.json === true,
    config.report,
  );
}

async function runGitleaksDetectors(input: {
  roots: ReturnType<typeof resolveRoots>;
  config: AppConfig;
  extraExclude: string[];
  version?: string;
  warn: (message: string) => void;
  detectors: DetectorResult[];
  occurrences: Occurrence[];
  onFinding: (occ: Occurrence) => void;
  env: NodeJS.ProcessEnv;
}): Promise<void> {
  if (input.config.detectors.gitleaks.enabled) {
    const merged = await runAcrossRoots(
      "gitleaks",
      input.roots,
      async (root) => {
        if (root.git.kind === "bare") {
          return {
            detector: skippedDetector("gitleaks", true, "bare-repository"),
            occurrences: [],
          };
        }
        return runGitleaksOnRoot({
          root,
          history: false,
          config: input.config,
          extraExclude: input.extraExclude,
          ...(input.version === undefined ? {} : { version: input.version }),
          warn: input.warn,
          env: input.env,
        });
      },
      input.onFinding,
    );
    input.detectors.push(merged.detector);
    input.occurrences.push(...merged.occurrences);
  } else {
    input.detectors.push(skippedDetector("gitleaks", false));
  }

  if (input.config.detectors.gitleaks.history) {
    const merged = await runAcrossRoots(
      "gitleaks-history",
      input.roots,
      async (root) => {
        if (root.git.kind === "none") {
          return {
            detector: skippedDetector(
              "gitleaks-history",
              true,
              root.git.reason ?? "not-a-git-repository",
            ),
            occurrences: [],
          };
        }
        return runGitleaksOnRoot({
          root,
          history: true,
          config: input.config,
          extraExclude: input.extraExclude,
          ...(input.version === undefined ? {} : { version: input.version }),
          warn: input.warn,
          env: input.env,
        });
      },
      input.onFinding,
    );
    input.detectors.push(merged.detector);
    input.occurrences.push(...merged.occurrences);
  } else {
    input.detectors.push(skippedDetector("gitleaks-history", false));
  }
}

async function runTrufflehogDetectors(input: {
  roots: ReturnType<typeof resolveRoots>;
  config: AppConfig;
  extraExclude: string[];
  version?: string;
  detectors: DetectorResult[];
  occurrences: Occurrence[];
  onFinding: (occ: Occurrence) => void;
  env: NodeJS.ProcessEnv;
}): Promise<void> {
  if (input.config.detectors.trufflehog.enabled) {
    const merged = await runAcrossRoots(
      "trufflehog",
      input.roots,
      async (root) => {
        if (root.git.kind === "bare") {
          return {
            detector: skippedDetector("trufflehog", true, "bare-repository"),
            occurrences: [],
          };
        }
        return runTrufflehogOnRoot({
          root,
          history: false,
          config: input.config,
          extraExclude: input.extraExclude,
          ...(input.version === undefined ? {} : { version: input.version }),
          env: input.env,
        });
      },
      input.onFinding,
    );
    input.detectors.push(merged.detector);
    input.occurrences.push(...merged.occurrences);
  } else {
    input.detectors.push(skippedDetector("trufflehog", false));
  }

  if (input.config.detectors.trufflehog.history) {
    const merged = await runAcrossRoots(
      "trufflehog-history",
      input.roots,
      async (root) => {
        if (root.git.kind === "none") {
          return {
            detector: skippedDetector(
              "trufflehog-history",
              true,
              root.git.reason ?? "not-a-git-repository",
            ),
            occurrences: [],
          };
        }
        return runTrufflehogOnRoot({
          root,
          history: true,
          config: input.config,
          extraExclude: input.extraExclude,
          ...(input.version === undefined ? {} : { version: input.version }),
          env: input.env,
        });
      },
      input.onFinding,
    );
    input.detectors.push(merged.detector);
    input.occurrences.push(...merged.occurrences);
  } else {
    input.detectors.push(skippedDetector("trufflehog-history", false));
  }
}

async function runAcrossRoots(
  name: DetectorName,
  roots: ReturnType<typeof resolveRoots>,
  run: (root: ReturnType<typeof resolveRoots>[number]) => Promise<{
    detector: DetectorResult;
    occurrences: Occurrence[];
  }>,
  onFinding: (occ: Occurrence) => void,
): Promise<{ detector: DetectorResult; occurrences: Occurrence[] }> {
  const occurrences: Occurrence[] = [];
  let status: DetectorResult["status"] = "completed";
  let error: string | undefined;
  let enabled = true;
  let version: string | undefined;
  for (const root of roots) {
    const result = await run(root);
    enabled = result.detector.enabled;
    version = result.detector.version ?? version;
    occurrences.push(...result.occurrences);
    for (const occurrence of result.occurrences) onFinding(occurrence);
    if (result.detector.status === "failed") {
      status = "failed";
      error = result.detector.error;
    } else if (
      result.detector.status === "skipped" &&
      status === "completed" &&
      occurrences.length === 0
    ) {
      status = "skipped";
      error = result.detector.error;
    } else if (result.detector.status === "completed") {
      if (status === "skipped") {
        status = "completed";
        error = undefined;
      }
    }
  }
  return {
    detector: {
      name,
      enabled,
      status,
      ...(version === undefined ? {} : { version }),
      ...(error === undefined ? {} : { error }),
    },
    occurrences,
  };
}

/** True when `policyPath` resolves to, or inside, any scan root. */
function pathInsideRoots(policyPath: string, roots: RootRecord[], cwd: string): boolean {
  if (!policyPath) return false;
  if (isPackagedPolicyPath(policyPath)) return false;
  const absolute = path.resolve(cwd, policyPath);
  let real: string | undefined;
  try {
    real = fs.realpathSync(absolute);
  } catch {
    // Missing files are reported by whoever loads them; only containment here.
  }
  return roots.some((root) =>
    [absolute, real].some(
      (candidate) =>
        candidate !== undefined &&
        (candidate === root.realPath || candidate.startsWith(`${root.realPath}${path.sep}`)),
    ),
  );
}

/** Name of the first admin policy path that lives inside a scan root, if any. */
function adminPolicyInsideRoots(
  config: AppConfig,
  roots: RootRecord[],
  cwd: string,
): string | undefined {
  const candidates: Array<[string, string]> = [
    [
      "detectors.native.rulesD",
      config.detectors.native.enabled ? config.detectors.native.rulesD : "",
    ],
    ["detectors.gitleaks.config", config.detectors.gitleaks.config],
    ["detectors.gitleaks.ignore", config.detectors.gitleaks.ignore],
    ["detectors.trufflehog.config", config.detectors.trufflehog.config],
    ["llm.instructions", config.llm.enabled ? config.llm.instructions : ""],
  ];
  if (config.detectors.classifier.enabled) {
    candidates.push(["classifier.executable", config.detectors.classifier.executable]);
  }
  for (const [name, value] of candidates) {
    if (pathInsideRoots(value, roots, cwd)) return name;
  }
  return undefined;
}

function finish(
  result: ScanResult,
  cwd: string,
  outputDir: string,
  cli: CliOverrides,
  stdout: { write(chunk: string): void },
  asJson: boolean,
  report: Pick<AppConfig["report"], "enabled" | "includeRaw">,
): ScanResult {
  const resolved = path.resolve(cwd, outputDir);
  const artifacts = report.enabled
    ? writeArtifacts(result, resolved, {
        showSuppressed: cli.showSuppressed === true,
        showHistoryCommits: cli.showHistoryCommits === true,
        includeRaw: report.includeRaw,
      })
    : null;
  const final = { ...result, artifacts };
  if (asJson) {
    stdout.write(`${JSON.stringify(publicManifest(final, report.includeRaw), null, 2)}\n`);
  } else {
    stdout.write(formatHumanSummary(final));
  }
  return final;
}

export { parseArgs, HELP_TEXT };
