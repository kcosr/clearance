import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stringify } from "smol-toml";
import { afterEach, describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { runClearance } from "../src/scan.js";
import type { ValidatorRuntime } from "../src/llm/runtime.js";

const token = "NR_TOKEN_SYNTHETIC";
const temporary: string[] = [];
afterEach(() => {
  for (const dir of temporary.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-no-report-"));
  temporary.push(dir);
  const root = path.join(dir, "input"),
    rules = path.join(dir, "rules");
  fs.mkdirSync(root);
  fs.mkdirSync(rules);
  fs.writeFileSync(path.join(root, "app.txt"), `access=${token}\n`);
  fs.writeFileSync(
    path.join(rules, "rules.toml"),
    stringify({
      schema_version: "clearance-rules/1",
      rules: [
        {
          id: "synthetic-token",
          type: "regex",
          pattern: "NR_TOKEN_[A-Z]+",
          severity: "high",
          category: "credential",
        },
      ],
    }),
  );
  const config = defaultConfig();
  config.detectors.native.rulesD = rules;
  config.detectors.gitleaks.enabled = false;
  config.detectors.trufflehog.enabled = false;
  config.report.outputDir = path.join(dir, "reports");
  const configPath = path.join(dir, "config.toml");
  const run = async (flags: string[] = [], runtime?: ValidatorRuntime) => {
    fs.writeFileSync(configPath, stringify(config));
    let stdout = "",
      stderr = "";
    const errorStream = {
      isTTY: true,
      write: (chunk: string) => {
        stderr += chunk;
      },
    };
    const result = await runClearance({
      argv: ["--config", configPath, ...flags, root],
      cwd: dir,
      env: {},
      stdout: {
        write: (chunk) => {
          stdout += chunk;
        },
      },
      stderr: errorStream,
      ...(runtime ? { llmRuntime: runtime } : {}),
    });
    return { result, stdout, stderr };
  };
  return { dir, root, config, configPath, run };
}

describe("report generation and terminal output", () => {
  it.each([
    [true, [], true],
    [false, [], false],
    [true, ["--no-report"], false],
    [false, ["--report"], true],
    [false, ["--report", "--no-report"], false],
    [true, ["--no-report", "--report"], true],
  ] as const)("resolves config=%s flags=%s to enabled=%s", async (configured, flags, enabled) => {
    const f = fixture();
    f.config.report.enabled = configured;
    const { result, stdout } = await f.run(["--json", ...flags]);
    const parsed = JSON.parse(stdout);
    expect(parsed).toMatchObject({
      schemaVersion: "clearance.report/v1",
      outcome: "denied",
      exitCode: 2,
      clusters: [{ path: "app.txt", effectiveStatus: "open" }],
      occurrences: [{ scanner: "native" }],
    });
    expect(stdout).not.toContain(token);
    expect(fs.existsSync(f.config.report.outputDir)).toBe(enabled);
    if (enabled) {
      expect(result.artifacts).not.toBeNull();
      expect(parsed).toEqual(JSON.parse(fs.readFileSync(result.artifacts!.manifest, "utf8")));
    } else expect(result.artifacts).toBeNull();
  });

  it("keeps live raw hits and a human summary without report paths; quiet retains only the summary", async () => {
    const f = fixture();
    const live = await f.run(["--no-report"]);
    expect(live.stderr).toContain(`value="${token}"`);
    expect(live.stdout).toContain("outcome: denied (exit 2)");
    expect(live.stdout).toContain("Report files: disabled");
    expect(live.stdout).not.toContain("Markdown report:");
    expect(live.stderr).not.toContain("writing reports");
    const quiet = await f.run(["--no-report", "--quiet"]);
    expect(quiet.stdout).toBe(live.stdout);
    expect(quiet.stderr).toBe("");
    expect(fs.existsSync(f.config.report.outputDir)).toBe(false);
  });

  it("controls JSON raw values independently of live output and report generation", async () => {
    const f = fixture();
    f.config.report.enabled = false;
    f.config.report.includeRaw = true;
    const raw = await f.run(["--json", "--quiet"]);
    expect(JSON.parse(raw.stdout).clusters[0].raw).toBe(token);
    expect(raw.stderr).toBe("");
    const redacted = await f.run(["--json", "--no-include-raw", "--progress"]);
    expect(redacted.stdout).not.toContain(token);
    expect(redacted.stderr).toContain(token);
    f.config.report.includeRaw = false;
    expect(JSON.parse((await f.run(["--json", "--include-raw"])).stdout).clusters[0].raw).toBe(
      token,
    );
    expect(fs.existsSync(f.config.report.outputDir)).toBe(false);
  });

  it("does not touch existing reports or require a writable report destination", async () => {
    const f = fixture();
    fs.mkdirSync(f.config.report.outputDir);
    for (const name of ["manifest.json", "report.md", "report.html"])
      fs.writeFileSync(path.join(f.config.report.outputDir, name), "keep existing report");
    await f.run(["--no-report"]);
    for (const name of fs.readdirSync(f.config.report.outputDir))
      expect(fs.readFileSync(path.join(f.config.report.outputDir, name), "utf8")).toBe(
        "keep existing report",
      );
    const blocked = path.join(f.dir, "not-a-directory");
    fs.writeFileSync(blocked, "unchanged");
    const result = await f.run(["--no-report", "--output", path.join(blocked, "reports")]);
    expect(result.result.outcome).toBe("denied");
    expect(fs.readFileSync(blocked, "utf8")).toBe("unchanged");
  });

  it("does not exclude an unused output directory that is the scan root", async () => {
    const f = fixture();
    const { result } = await f.run(["--no-report", "--output", f.root]);
    expect(result.occurrences).toHaveLength(1);
    expect(result.outcome).toBe("denied");
    expect(fs.readdirSync(f.root)).toEqual(["app.txt"]);
  });

  it("includes validation verdicts in JSON without report files", async () => {
    const f = fixture();
    f.config.llm.enabled = true;
    f.config.llm.canOverride = true;
    const { stdout, stderr } = await f.run(["--json", "--no-report", "--progress"], {
      async validateBatch(request) {
        return {
          batchId: request.batchId,
          verdicts: request.clusters.map((c) => ({
            clusterId: c.clusterId,
            status: "false_positive",
            confidence: 1,
            rationale: "Synthetic test value.",
          })),
        };
      },
    });
    expect(JSON.parse(stdout)).toMatchObject({
      outcome: "clean",
      exitCode: 0,
      llm: { status: "complete" },
      clusters: [
        {
          effectiveStatus: "suppressed",
          llm: { status: "false_positive", rationale: "Synthetic test value." },
        },
      ],
    });
    expect(stderr).toContain('false_positive: "Synthetic test value."');
    expect(fs.existsSync(f.config.report.outputDir)).toBe(false);
  });

  it.each(["unused", "scan-root"])(
    "does not reserve %s output paths for an external trace",
    async (output) => {
      const f = fixture();
      fs.mkdirSync(path.join(f.root, "clearance-report"));
      fs.renameSync(path.join(f.root, "app.txt"), path.join(f.root, "clearance-report", "app.txt"));
      f.config.report.enabled = false;
      if (output === "scan-root") f.config.report.outputDir = f.root;
      f.config.llm.enabled = true;
      f.config.llm.traceFile = path.join(f.dir, "elsewhere", "trace.jsonl");
      const { result, stdout } = await f.run(["--json"], {
        async validateBatch(request) {
          return {
            batchId: request.batchId,
            verdicts: request.clusters.map((c) => ({
              clusterId: c.clusterId,
              status: "confirmed",
              confidence: 1,
              rationale: "Credential control.",
            })),
          };
        },
      });
      expect(result.outcome).toBe("denied");
      expect(result.occurrences).toHaveLength(1);
      expect(result.walk.excludedByConfig).toBe(0);
      expect(JSON.parse(stdout).clusters[0].llm.status).toBe("confirmed");
      expect(fs.existsSync(f.config.llm.traceFile)).toBe(true);
      expect(fs.readdirSync(f.root)).toEqual(["clearance-report"]);
      expect(fs.readdirSync(path.join(f.root, "clearance-report"))).toEqual(["app.txt"]);
      if (output === "unused") expect(fs.existsSync(f.config.report.outputDir)).toBe(false);
    },
  );

  it("retains explicitly configured LLM debug tracing separately", async () => {
    const f = fixture();
    f.config.llm.enabled = true;
    f.config.llm.traceFile = "debug.jsonl";
    await f.run(["--no-report", "--quiet"], {
      async validateBatch(request) {
        return {
          batchId: request.batchId,
          verdicts: request.clusters.map((c) => ({
            clusterId: c.clusterId,
            status: "confirmed",
            confidence: 1,
            rationale: "Credential control.",
          })),
        };
      },
    });
    expect(fs.readdirSync(f.config.report.outputDir).sort()).toEqual(["debug.html", "debug.jsonl"]);
  });

  it.each(["disabled-detectors", "missing-root", "missing-detector", "inside-policy"])(
    "honors disabled reports for %s scan errors",
    async (kind) => {
      const f = fixture();
      f.config.report.enabled = false;
      if (kind === "disabled-detectors") f.config.detectors.native.enabled = false;
      if (kind === "missing-root") fs.rmSync(f.root, { recursive: true });
      if (kind === "missing-detector") {
        f.config.detectors.gitleaks.enabled = true;
        f.config.detectors.gitleaks.bin = path.join(f.dir, "missing-gitleaks");
      }
      if (kind === "inside-policy") f.config.detectors.native.rulesD = f.root;
      const { result, stdout } = await f.run(["--json"]);
      expect(result.exitCode).toBe(3);
      expect(result.artifacts).toBeNull();
      expect(JSON.parse(stdout)).toMatchObject({ outcome: "error", exitCode: 3 });
      expect(fs.existsSync(f.config.report.outputDir)).toBe(false);
    },
  );

  it("includes coverage holes in stdout-only JSON", async () => {
    const f = fixture();
    fs.unlinkSync(path.join(f.root, "app.txt"));
    fs.writeFileSync(path.join(f.root, "archive.zip"), "PK");
    const { stdout } = await f.run(["--json", "--no-report"]);
    expect(JSON.parse(stdout)).toMatchObject({
      outcome: "incomplete",
      exitCode: 2,
      coverage: [{ path: "archive.zip", reason: "archive" }],
    });
    expect(fs.existsSync(f.config.report.outputDir)).toBe(false);
  });

  it.each(["invalid-config", "missing-config", "invalid-args"])(
    "writes no reports for %s before scanning",
    async (kind) => {
      const f = fixture();
      let stdout = "",
        stderr = "";
      if (kind === "invalid-config")
        fs.writeFileSync(f.configPath, '[report]\nenabled = "invalid"\n');
      const { exitCode, artifacts } = await runClearance({
        argv: [
          "--json",
          "--no-report",
          ...(kind === "invalid-args" ? ["--unknown"] : ["--config", f.configPath]),
        ],
        cwd: f.dir,
        env: {},
        stdout: {
          write: (s) => {
            stdout += s;
          },
        },
        stderr: {
          write: (s) => {
            stderr += s;
          },
        },
      });
      expect(exitCode).toBe(3);
      expect(artifacts).toBeNull();
      expect(stderr).toContain("error:");
      if (kind === "invalid-args") expect(stdout).toBe("");
      else
        expect(JSON.parse(stdout)).toMatchObject({ outcome: "error", exitCode: 3, clusters: [] });
      expect(fs.readdirSync(f.dir).sort()).toEqual(
        kind === "invalid-config" ? ["config.toml", "input", "rules"] : ["input", "rules"],
      );
    },
  );
});
