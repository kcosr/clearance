import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { applyCli, defaultConfig, loadConfig } from "../src/config.js";
import { parseArgs } from "../src/cli-parse.js";
import { tempDir, writeTree } from "./helpers.js";

describe("config", () => {
  it("starts from packaged defaults", () => {
    const config = defaultConfig();
    expect(config.report.failOn).toBe("high");
    expect(config.report.enabled).toBe(true);
    expect(config.llm.enabled).toBe(false);
    expect(config.detectors.gitleaks.history).toBe(false);
    expect(config.scan.exclude).toContain(".git/**");
  });

  it("applies file, env, then CLI field-by-field", () => {
    const dir = tempDir("clearance-config-");
    writeTree(dir, {
      "config.toml": `
[report]
failOn = "medium"
outputDir = "./from-file"
[llm]
enabled = true
mode = "validate"
canOverride = false
failurePolicy = "accept"
maxRepairs = 1
timeoutMs = 120000
partialOnTimeout = true
instructions = ""
instructionsText = ""
[llm.batch]
maxTokens = 4096
maxClusters = 50
maxBytes = 16384
contextLines = 2
concurrency = 1
`,
    });
    const loaded = loadConfig(
      { configPath: path.join(dir, "config.toml"), roots: [], failOn: "critical", outputDir: "./from-cli" },
      { CLEARANCE_OUTPUT: "./from-env", CLEARANCE_FAIL_ON: "low" },
    );
    expect(loaded.report.failOn).toBe("critical");
    expect(loaded.report.outputDir).toBe("./from-cli");
    expect(loaded.llm.enabled).toBe(true);
  });

  it("appends exclude and suppress strings", () => {
    const config = applyCli(defaultConfig(), {
      roots: [],
      exclude: ["tmp/**"],
      suppressStrings: ["fixture"],
    });
    expect(config.scan.exclude).toContain("tmp/**");
    expect(config.scan.exclude).toContain(".git/**");
    expect(config.suppress.strings).toEqual(["fixture"]);
  });

  it("replaces include when --include is passed", () => {
    const config = applyCli(defaultConfig(), { roots: [], include: ["app.env"] });
    expect(config.scan.include).toEqual(["app.env"]);
  });

  it("maps --on-opaque onto all three coverage policies", () => {
    const config = applyCli(defaultConfig(), { roots: [], onOpaque: "skip" });
    expect(config.scan.onArchive).toBe("skip");
    expect(config.scan.onOversize).toBe("skip");
    expect(config.scan.onUnreadable).toBe("skip");
  });

  it("errors when a required config file is missing", () => {
    expect(() => loadConfig({ configPath: "/no/such/clearance.toml", roots: [] })).toThrow(/not found/);
  });

  it("parses boolean detector flags", () => {
    const cli = parseArgs(["--no-gitleaks", "--gitleaks-history", "--no-llm", "src"]);
    expect(cli.gitleaks).toBe(false);
    expect(cli.gitleaksHistory).toBe(true);
    expect(cli.llm).toBe(false);
    expect(cli.roots).toEqual(["src"]);
  });

  it("rejects unknown flags", () => {
    expect(() => parseArgs(["--wat"])).toThrow(/unknown flag/);
  });

  it("ignores a missing /etc config and keeps defaults", () => {
    const loaded = loadConfig({ roots: [] }, {});
    expect(loaded.model.baseURL).toBe("http://127.0.0.1:8000/v1");
    expect(loaded.model.model).toBe("local-model");
    expect(loaded.model.reasoning).toBe("off");
    expect(fs.existsSync(loaded.detectors.gitleaks.config)).toBe(true);
  });
  it("layers an explicit --config on top of the system config", () => {
    // /etc/clearance/config.toml is a layer *beneath* --config, not an
    // alternative to it, so a site default survives a partial per-run config.
    const dir = tempDir("clearance-cfg-");
    const systemPath = path.join(dir, "system.toml");
    const userPath = path.join(dir, "user.toml");
    fs.writeFileSync(systemPath, '[report]\nfailOn = "critical"\n\n[scan]\nmaxDepth = 7\n');
    fs.writeFileSync(userPath, '[report]\nfailOn = "low"\n');
    const loaded = loadConfig({ configPath: userPath, roots: [] }, {}, systemPath);
    expect(loaded.report.failOn).toBe("low");
    expect(loaded.scan.maxDepth).toBe(7);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("parses --include-raw and maps it to [report].includeRaw", () => {
    expect(loadConfig({ roots: [] }, {}).report.includeRaw).toBe(false);
    expect(parseArgs(["--include-raw"]).includeRaw).toBe(true);
    expect(parseArgs(["--no-include-raw"]).includeRaw).toBe(false);
    expect(loadConfig({ includeRaw: true, roots: [] }, {}).report.includeRaw).toBe(true);
  });
  it("exposes scanner bounds as configurable limits", () => {
    const defaults = loadConfig({ roots: [] }, {});
    expect(defaults.limits.scannerTimeoutMs).toBe(120_000);
    expect(defaults.limits.maxFindings).toBe(10_000);

    const dir = tempDir("clearance-limits-");
    const cfg = path.join(dir, "c.toml");
    fs.writeFileSync(cfg, "[limits]\nscannerTimeoutMs = 600000\nmaxFindings = 25\n");
    const loaded = loadConfig({ configPath: cfg, roots: [] }, {});
    expect(loaded.limits.scannerTimeoutMs).toBe(600_000);
    expect(loaded.limits.maxFindings).toBe(25);
    // untouched keys keep their defaults through the merge
    expect(loaded.limits.versionTimeoutMs).toBe(5_000);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
