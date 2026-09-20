import { SEVERITIES, type Severity } from "./types.js";
import type { AppConfig, CliOverrides } from "./config.js";

const REASONING = ["off", "minimal", "low", "medium", "high", "xhigh", "max"] as const;

export const HELP_TEXT = `clearance [paths...] [flags]

Scan local directories and report whether they are cleared to share.

  --config PATH
  --output DIR
  --report / --no-report              Enable/disable report files (default enabled)
  --fail-on low|medium|high|critical
  --native / --no-native
  --progress                         Show progress and raw live findings on stderr
  --quiet                            Suppress progress and live findings (warnings/errors remain)
  --classifier / --no-classifier       External whole-content discovery
  --gitleaks / --no-gitleaks
  --gitleaks-history / --no-gitleaks-history
  --trufflehog / --no-trufflehog
  --trufflehog-history / --no-trufflehog-history
  --show-history-commits
  --llm / --no-llm
  --llm-override / --no-llm-override
  --llm-mode validate
  --llm-instructions PATH
  --llm-trace PATH                   append JSONL debug trace of each LLM batch (0600)
  --llm-trace-detail metadata|full   full records request+raw response (contains secrets)
  --model NAME
  --reasoning off|minimal|low|medium|high|xhigh|max
  --chat-template-thinking true|false
  --show-suppressed
  --include-raw / --no-include-raw   publish original values in reports and JSON stdout
  --exclude-test-fixtures / --no-exclude-test-fixtures   Exclude test findings from outcome; still scan them (default off)
  --include GLOB
  --exclude GLOB
  --on-archive skip|incomplete
  --on-opaque skip|incomplete
  --suppress-string STRING
  --json                             Full scan result on stdout; progress stays on stderr
  --version
  --help
`;

function takeValue(argv: string[], i: number, flag: string): [string, number] {
  const current = argv[i];
  if (current && current.includes("=") && current.startsWith("--")) {
    return [current.slice(current.indexOf("=") + 1), i];
  }
  const next = argv[i + 1];
  if (next === undefined || next.startsWith("--")) {
    throw Object.assign(new Error(`missing value for ${flag}`), { code: "bad-flag" });
  }
  return [next, i + 1];
}

function parseBool(value: string, flag: string): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  throw Object.assign(new Error(`${flag} must be true or false`), { code: "bad-flag" });
}

export function parseArgs(argv: string[]): CliOverrides {
  const cli: CliOverrides = { roots: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--") {
      cli.roots.push(...argv.slice(i + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      cli.roots.push(arg);
      continue;
    }
    const [flag, inline] = splitFlag(arg);
    const read = (name: string): string => {
      if (inline !== undefined) return inline;
      const [value, next] = takeValue(argv, i, name);
      i = next;
      return value;
    };
    switch (flag) {
      case "--config":
        cli.configPath = read("--config");
        break;
      case "--report":
        cli.report = true;
        break;
      case "--no-report":
        cli.report = false;
        break;
      case "--output":
        cli.outputDir = read("--output");
        break;
      case "--fail-on": {
        const value = read("--fail-on");
        if (!SEVERITIES.includes(value as Severity)) {
          throw Object.assign(new Error(`invalid --fail-on: ${value}`), { code: "bad-flag" });
        }
        cli.failOn = value as Severity;
        break;
      }
      case "--native":
        cli.native = true;
        break;
      case "--no-native":
        cli.native = false;
        break;
      case "--progress":
        cli.progress = true;
        break;
      case "--quiet":
        cli.progress = false;
        break;
      case "--classifier":
        cli.classifier = true;
        break;
      case "--no-classifier":
        cli.classifier = false;
        break;
      case "--gitleaks":
        cli.gitleaks = true;
        break;
      case "--no-gitleaks":
        cli.gitleaks = false;
        break;
      case "--gitleaks-history":
        cli.gitleaksHistory = true;
        break;
      case "--no-gitleaks-history":
        cli.gitleaksHistory = false;
        break;
      case "--trufflehog":
        cli.trufflehog = true;
        break;
      case "--no-trufflehog":
        cli.trufflehog = false;
        break;
      case "--trufflehog-history":
        cli.trufflehogHistory = true;
        break;
      case "--no-trufflehog-history":
        cli.trufflehogHistory = false;
        break;
      case "--show-history-commits":
        cli.showHistoryCommits = true;
        break;
      case "--llm":
        cli.llm = true;
        break;
      case "--no-llm":
        cli.llm = false;
        break;
      case "--llm-override":
        cli.llmOverride = true;
        break;
      case "--no-llm-override":
        cli.llmOverride = false;
        break;
      case "--llm-mode": {
        const value = read("--llm-mode");
        if (value !== "validate") {
          throw Object.assign(new Error(`unsupported --llm-mode: ${value}`), { code: "bad-flag" });
        }
        cli.llmMode = "validate";
        break;
      }
      case "--llm-trace":
        cli.llmTrace = read("--llm-trace");
        break;
      case "--llm-trace-detail": {
        const value = read("--llm-trace-detail");
        if (value !== "metadata" && value !== "full") {
          throw new Error(`--llm-trace-detail must be metadata|full, got "${value}"`);
        }
        cli.llmTraceDetail = value;
        break;
      }
      case "--llm-instructions":
        cli.llmInstructions = read("--llm-instructions");
        break;
      case "--model":
        cli.model = read("--model");
        break;
      case "--reasoning": {
        const value = read("--reasoning");
        if (!REASONING.includes(value as AppConfig["model"]["reasoning"])) {
          throw Object.assign(new Error(`invalid --reasoning: ${value}`), { code: "bad-flag" });
        }
        cli.reasoning = value as AppConfig["model"]["reasoning"];
        break;
      }
      case "--chat-template-thinking":
        cli.chatTemplateThinking = parseBool(read("--chat-template-thinking"), flag);
        break;
      case "--show-suppressed":
        cli.showSuppressed = true;
        break;
      case "--include-raw":
        cli.includeRaw = true;
        break;
      case "--no-include-raw":
        cli.includeRaw = false;
        break;
      case "--exclude-test-fixtures":
        cli.excludeTestFixtures = true;
        break;
      case "--no-exclude-test-fixtures":
        cli.excludeTestFixtures = false;
        break;
      case "--include":
        cli.include = [...(cli.include ?? []), read("--include")];
        break;
      case "--exclude":
        cli.exclude = [...(cli.exclude ?? []), read("--exclude")];
        break;
      case "--on-archive": {
        const value = read("--on-archive");
        if (value !== "skip" && value !== "incomplete") {
          throw Object.assign(new Error(`invalid --on-archive: ${value}`), { code: "bad-flag" });
        }
        cli.onArchive = value;
        break;
      }
      case "--on-opaque": {
        const value = read("--on-opaque");
        if (value !== "skip" && value !== "incomplete") {
          throw Object.assign(new Error(`invalid --on-opaque: ${value}`), { code: "bad-flag" });
        }
        cli.onOpaque = value;
        break;
      }
      case "--suppress-string":
        cli.suppressStrings = [...(cli.suppressStrings ?? []), read("--suppress-string")];
        break;
      case "--json":
        cli.json = true;
        break;
      case "--version":
        cli.version = true;
        break;
      case "--help":
      case "-h":
        cli.help = true;
        break;
      default:
        throw Object.assign(new Error(`unknown flag: ${flag}`), { code: "bad-flag" });
    }
  }
  return cli;
}

function splitFlag(arg: string): [string, string | undefined] {
  const eq = arg.indexOf("=");
  if (eq === -1) return [arg, undefined];
  return [arg.slice(0, eq), arg.slice(eq + 1)];
}
