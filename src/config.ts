import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import { z } from "zod";
import { packagedPolicyPath } from "./packaged-policy.js";
import { SEVERITIES, type CoveragePolicy, type Severity } from "./types.js";

import { ClassifierConfigSchema, DEFAULT_CLASSIFIER } from "./classifier/config.js";

const SeveritySchema = z.enum(SEVERITIES);
const CoverageSchema = z.enum(["skip", "incomplete"]);
const ReasoningSchema = z.enum(["off", "minimal", "low", "medium", "high", "xhigh", "max"]);

export const ConfigSchema = z.object({
  scan: z.object({
    excludeTestFixtures: z.boolean(),
    include: z.array(z.string()),
    exclude: z.array(z.string()),
    maxFileBytes: z.number().int().min(0),
    maxDepth: z.number().int().min(1),
    skipExtensions: z.array(z.string()),
    archiveExtensions: z.array(z.string()),
    onUnreadable: CoverageSchema,
    onOversize: CoverageSchema,
    onArchive: CoverageSchema,
  }),
  detectors: z.object({
    classifier: ClassifierConfigSchema,
    native: z.object({
      enabled: z.boolean(),
      rulesD: z.string(),
    }),
    gitleaks: z.object({
      enabled: z.boolean(),
      history: z.boolean(),
      bin: z.string(),
      config: z.string(),
      ignore: z.string(),
    }),
    trufflehog: z.object({
      enabled: z.boolean(),
      history: z.boolean(),
      bin: z.string(),
      config: z.string(),
      includeDetectors: z.array(z.string()),
      excludeDetectors: z.array(z.string()),
    }),
  }),
  model: z.object({
    api: z.enum(["chat_completions", "responses"]),
    baseURL: z.string(),
    model: z.string(),
    apiKeyEnv: z.string(),
    timeoutMs: z.number().int().positive(),
    maxRetries: z.number().int().min(0).max(2),
    contextWindow: z.number().int().positive(),
    reasoning: ReasoningSchema,
    chatTemplateThinking: z.boolean().optional(),
    maxOutputTokens: z.number().int().min(0),
  }),
  llm: z.object({
    enabled: z.boolean(),
    mode: z.literal("validate"),
    canOverride: z.boolean(),
    failurePolicy: z.enum(["accept", "fallback", "fail"]),
    maxRepairs: z.number().int().min(0).max(2),
    timeoutMs: z.number().int().positive(),
    partialOnTimeout: z.boolean(),
    instructions: z.string(),
    instructionsText: z.string(),
    traceFile: z.string(),
    traceDetail: z.enum(["metadata", "full"]),
    tools: z.object({
      read: z.boolean(),
      maxLines: z.number().int().positive(),
      maxCalls: z.number().int().min(0),
    }),
    batch: z.object({
      maxTokens: z.number().int().positive(),
      maxClusters: z.number().int().positive(),
      maxBytes: z.number().int().positive(),
      contextLines: z.number().int().min(0),
      concurrency: z.number().int().min(1),
    }),
  }),
  suppress: z.object({
    strings: z.array(z.string()),
    patterns: z.array(z.string()),
    ignoreCase: z.boolean(),
  }),
  report: z.object({
    enabled: z.boolean(),
    outputDir: z.string(),
    formats: z.array(z.enum(["json", "markdown", "html"])),
    failOn: SeveritySchema,
    includeRaw: z.boolean(),
    progress: z.enum(["auto", "on", "off"]),
  }),
  limits: z.object({
    scannerTimeoutMs: z.number().int().positive(),
    versionTimeoutMs: z.number().int().positive(),
    maxStdoutBytes: z.number().int().positive(),
    maxReportBytes: z.number().int().positive(),
    maxFindings: z.number().int().positive(),
  }),
});

export type AppConfig = z.infer<typeof ConfigSchema>;

export function packageRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function shareFile(name: string): string {
  return packagedPolicyPath(name) ?? path.join(packageRoot(), "examples", name);
}

declare const CLEARANCE_BUILD_VERSION: string | undefined;

export const PACKAGE_VERSION =
  typeof CLEARANCE_BUILD_VERSION === "string" ? CLEARANCE_BUILD_VERSION : "0.1.0";

export function defaultConfig(): AppConfig {
  return {
    scan: {
      excludeTestFixtures: false,
      include: [],
      exclude: [".git/**", "node_modules/**", "dist/**", ".cache/**"],
      maxFileBytes: 1_048_576,
      maxDepth: 32,
      skipExtensions: [
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".wav",
      ],
      archiveExtensions: [".zip", ".tar", ".tgz", ".gz", ".7z", ".rar", ".jar", ".war", ".whl"],
      onUnreadable: "incomplete",
      onOversize: "incomplete",
      onArchive: "incomplete",
    },
    detectors: {
      classifier: structuredClone(DEFAULT_CLASSIFIER),
      native: { enabled: true, rulesD: shareFile("rules.d") },
      gitleaks: {
        enabled: true,
        history: false,
        bin: "gitleaks",
        config: shareFile("gitleaks.toml"),
        ignore: shareFile("gitleaks.ignore"),
      },
      trufflehog: {
        enabled: true,
        history: false,
        bin: "trufflehog",
        config: "",
        includeDetectors: [],
        excludeDetectors: [],
      },
    },
    model: {
      api: "chat_completions",
      baseURL: "http://127.0.0.1:8000/v1",
      model: "local-model",
      apiKeyEnv: "",
      timeoutMs: 30_000,
      maxRetries: 1,
      contextWindow: 32_000,
      reasoning: "off",
      maxOutputTokens: 2048,
    },
    llm: {
      enabled: false,
      mode: "validate",
      canOverride: false,
      failurePolicy: "accept",
      maxRepairs: 1,
      timeoutMs: 120_000,
      partialOnTimeout: true,
      instructions: "",
      instructionsText: "",
      traceFile: "",
      traceDetail: "metadata",
      tools: { read: false, maxLines: 200, maxCalls: 8 },
      batch: {
        maxTokens: 4096,
        maxClusters: 50,
        maxBytes: 16_384,
        contextLines: 2,
        concurrency: 1,
      },
    },
    suppress: { strings: [], patterns: [], ignoreCase: false },
    report: {
      enabled: true,
      outputDir: "./clearance-report",
      formats: ["json", "markdown", "html"],
      failOn: "high",
      includeRaw: false,
      progress: "auto",
    },
    limits: {
      scannerTimeoutMs: 120_000,
      versionTimeoutMs: 5_000,
      maxStdoutBytes: 8_000_000,
      maxReportBytes: 16_000_000,
      maxFindings: 10_000,
    },
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function deepMerge(base: unknown, overlay: unknown): unknown {
  if (Array.isArray(overlay)) return overlay;
  if (!isPlainObject(overlay)) return overlay === undefined ? base : overlay;
  const left = isPlainObject(base) ? base : {};
  const out: Record<string, unknown> = { ...left };
  for (const [key, value] of Object.entries(overlay)) {
    out[key] = key in left ? deepMerge(left[key], value) : value;
  }
  return out;
}

export function loadTomlFile(filePath: string): Record<string, unknown> {
  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = parseToml(raw);
  if (!isPlainObject(parsed)) {
    throw Object.assign(new Error(`invalid config: ${filePath}`), { code: "config-invalid" });
  }
  return parsed;
}

export function applyEnv(config: AppConfig, env: NodeJS.ProcessEnv = process.env): AppConfig {
  const next = structuredClone(config);
  if (env.CLEARANCE_OUTPUT) next.report.outputDir = env.CLEARANCE_OUTPUT;
  if (env.CLEARANCE_LLM_TRACE) next.llm.traceFile = env.CLEARANCE_LLM_TRACE;
  if (env.CLEARANCE_LLM_TRACE_DETAIL === "full" || env.CLEARANCE_LLM_TRACE_DETAIL === "metadata") {
    next.llm.traceDetail = env.CLEARANCE_LLM_TRACE_DETAIL;
  }
  if (env.CLEARANCE_FAIL_ON) {
    next.report.failOn = SeveritySchema.parse(env.CLEARANCE_FAIL_ON);
  }
  return next;
}

export type CliOverrides = {
  configPath?: string;
  outputDir?: string;
  report?: boolean;
  failOn?: Severity;
  native?: boolean;
  classifier?: boolean;
  progress?: boolean;
  gitleaks?: boolean;
  gitleaksHistory?: boolean;
  trufflehog?: boolean;
  trufflehogHistory?: boolean;
  showHistoryCommits?: boolean;
  llm?: boolean;
  llmOverride?: boolean;
  llmMode?: "validate";
  llmInstructions?: string;
  llmTrace?: string;
  llmTraceDetail?: "metadata" | "full";
  model?: string;
  reasoning?: AppConfig["model"]["reasoning"];
  chatTemplateThinking?: boolean;
  showSuppressed?: boolean;
  includeRaw?: boolean;
  excludeTestFixtures?: boolean;
  include?: string[];
  exclude?: string[];
  onArchive?: CoveragePolicy;
  onOpaque?: CoveragePolicy;
  suppressStrings?: string[];
  json?: boolean;
  version?: boolean;
  help?: boolean;
  roots: string[];
};

export function emptyCli(): CliOverrides {
  return { roots: [] };
}

export function applyCli(config: AppConfig, cli: CliOverrides): AppConfig {
  const next = structuredClone(config);
  if (cli.report !== undefined) next.report.enabled = cli.report;
  if (cli.progress !== undefined) next.report.progress = cli.progress ? "on" : "off";
  if (cli.outputDir) next.report.outputDir = cli.outputDir;
  if (cli.failOn) next.report.failOn = cli.failOn;
  if (cli.excludeTestFixtures !== undefined)
    next.scan.excludeTestFixtures = cli.excludeTestFixtures;
  if (cli.includeRaw !== undefined) next.report.includeRaw = cli.includeRaw;
  if (cli.classifier !== undefined) next.detectors.classifier.enabled = cli.classifier;
  if (cli.native !== undefined) next.detectors.native.enabled = cli.native;
  if (cli.gitleaks !== undefined) next.detectors.gitleaks.enabled = cli.gitleaks;
  if (cli.gitleaksHistory !== undefined) next.detectors.gitleaks.history = cli.gitleaksHistory;
  if (cli.trufflehog !== undefined) next.detectors.trufflehog.enabled = cli.trufflehog;
  if (cli.trufflehogHistory !== undefined)
    next.detectors.trufflehog.history = cli.trufflehogHistory;
  if (cli.llm !== undefined) next.llm.enabled = cli.llm;
  if (cli.llmOverride !== undefined) next.llm.canOverride = cli.llmOverride;
  if (cli.llmMode) next.llm.mode = cli.llmMode;
  if (cli.llmInstructions) next.llm.instructions = cli.llmInstructions;
  if (cli.llmTrace) next.llm.traceFile = cli.llmTrace;
  if (cli.llmTraceDetail) next.llm.traceDetail = cli.llmTraceDetail;
  if (cli.model) next.model.model = cli.model;
  if (cli.reasoning) next.model.reasoning = cli.reasoning;
  if (cli.chatTemplateThinking !== undefined) {
    next.model.chatTemplateThinking = cli.chatTemplateThinking;
  }
  if (cli.include && cli.include.length > 0) next.scan.include = cli.include;
  if (cli.exclude && cli.exclude.length > 0) {
    next.scan.exclude = [...next.scan.exclude, ...cli.exclude];
  }
  if (cli.onArchive) next.scan.onArchive = cli.onArchive;
  if (cli.onOpaque) {
    next.scan.onArchive = cli.onOpaque;
    next.scan.onOversize = cli.onOpaque;
    next.scan.onUnreadable = cli.onOpaque;
  }
  if (cli.suppressStrings && cli.suppressStrings.length > 0) {
    next.suppress.strings = [...next.suppress.strings, ...cli.suppressStrings];
  }
  return next;
}

export const SYSTEM_CONFIG_PATH = "/etc/clearance/config.toml";

/**
 * Config file layers, lowest precedence first. `/etc/clearance/config.toml` is a
 * layer *beneath* an explicit `--config` / `CLEARANCE_CONFIG`, not an
 * alternative to it, so a site-wide default survives a per-run config that only
 * sets a few fields. A missing explicit file is an error; a missing system file
 * is not.
 */
export function resolveConfigFiles(
  cliPath: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
  systemPath: string = SYSTEM_CONFIG_PATH,
): Array<{ path: string; required: boolean }> {
  const layers: Array<{ path: string; required: boolean }> = [];
  if (fs.existsSync(systemPath)) layers.push({ path: systemPath, required: false });
  const explicit = cliPath ?? env.CLEARANCE_CONFIG;
  if (explicit && path.resolve(explicit) !== path.resolve(systemPath)) {
    layers.push({ path: explicit, required: true });
  }
  return layers;
}

export function loadConfig(
  cli: CliOverrides,
  env: NodeJS.ProcessEnv = process.env,
  systemPath: string = SYSTEM_CONFIG_PATH,
): AppConfig {
  let merged: unknown = defaultConfig();
  for (const file of resolveConfigFiles(cli.configPath, env, systemPath)) {
    if (!fs.existsSync(file.path)) {
      if (!file.required) continue;
      throw Object.assign(new Error(`config not found: ${file.path}`), { code: "config-missing" });
    }
    try {
      merged = deepMerge(merged, loadTomlFile(file.path));
    } catch (error) {
      if ((error as { code?: string }).code === "config-invalid") throw error;
      throw Object.assign(new Error(`invalid config: ${file.path}`), {
        code: "config-invalid",
        cause: error,
      });
    }
  }
  const schemaError = (error: unknown) => {
    // Only schema-owned field names enter diagnostics; never reflect config values or unknown keys.
    const classifierFields = new Set(Object.keys(ClassifierConfigSchema.shape));
    const fields =
      error instanceof z.ZodError
        ? [
            ...new Set(
              error.issues.flatMap((issue) => {
                const [a, b, c] = issue.path;
                return a === "detectors" &&
                  b === "classifier" &&
                  typeof c === "string" &&
                  classifierFields.has(c)
                  ? [`detectors.classifier.${c}`]
                  : [];
              }),
            ),
          ]
        : [];
    return Object.assign(
      new Error(
        fields.length
          ? `invalid config schema: check ${fields.join(", ")}`
          : "invalid config schema",
      ),
      { code: "config-invalid", cause: error },
    );
  };
  let parsed: AppConfig;
  try {
    parsed = ConfigSchema.parse(merged);
  } catch (error) {
    throw schemaError(error);
  }
  try {
    return ConfigSchema.parse(applyCli(applyEnv(parsed, env), cli));
  } catch (error) {
    throw schemaError(error);
  }
}

export function anyDetectorEnabled(config: AppConfig): boolean {
  return (
    config.detectors.classifier.enabled ||
    config.detectors.native.enabled ||
    config.detectors.gitleaks.enabled ||
    config.detectors.gitleaks.history ||
    config.detectors.trufflehog.enabled ||
    config.detectors.trufflehog.history
  );
}
