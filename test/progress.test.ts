import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stringify } from "smol-toml";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_CLASSIFIER, type ClassifierConfig } from "../src/classifier/config.js";
import { invokeClassifier } from "../src/classifier/process.js";
import { defaultConfig } from "../src/config.js";
import { classifierProgress, progressSink, type ClassifierProgress } from "../src/progress.js";
import { runClearance } from "../src/scan.js";

const executable = fs.realpathSync(process.execPath);
const privateDiagnostic = "PRIVATE-CHILD-DIAGNOSTIC";
const temporary: string[] = [];
afterEach(() => {
  for (const directory of temporary.splice(0))
    fs.rmSync(directory, { recursive: true, force: true });
});

const event = (completed = 0, total = 2): ClassifierProgress => ({
  version: 1,
  type: "progress",
  stage: "classifying",
  completed,
  total,
});

// Script arguments deliberately include --progress, just as a Bun deployment can.
const script = `
const fs=require('node:fs');
const mode=process.argv[2];
if(process.argv[3]!=='--progress')process.exit(9);
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',s=>input+=s);
process.stdin.on('end',()=>{
 const request=JSON.parse(input);
 const record=(completed,total=2,stage='classifying')=>JSON.stringify({version:1,type:'progress',stage,completed,total});
 if(mode==='limit')fs.writeSync(2,Array(32771).fill(record(0)).join('\\n')+'\\n');
 else if(mode==='oversize')fs.writeSync(2,'PRIVATE-CHILD-DIAGNOSTIC'.repeat(200));
 else {
  const first=record(0,2,'planning');
  fs.writeSync(2,first.slice(0,23));fs.writeSync(2,first.slice(23)+'\\n');
  fs.writeSync(2,'PRIVATE-CHILD-DIAGNOSTIC\\n');
  fs.writeSync(2,JSON.stringify({version:1,type:'progress',stage:'classifying',completed:1,total:2,detail:'PRIVATE-CHILD-DIAGNOSTIC'})+'\\n');
  fs.writeSync(2,record(1)+'\\n'+record(2));
 }
 process.stdout.write(JSON.stringify({version:2,status:'complete',findings:[{text:'secret',category:'confidential',reason:'private_fact'}]})+'\\n');
});
`;

function fixture(mode = "normal") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-progress-"));
  temporary.push(directory);
  const root = path.join(directory, "input");
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "private-filename.txt"), "secret");
  const helper = path.join(directory, "helper.cjs");
  fs.writeFileSync(helper, script);
  const config: ClassifierConfig = {
    ...structuredClone(DEFAULT_CLASSIFIER),
    enabled: true,
    executable,
    args: [helper, mode, "--progress"],
    timeoutMs: 5000,
    policy: {
      instructions: "Find private facts.",
      categories: [
        {
          id: "confidential",
          reasons: ["private_fact"],
          severity: "high",
          inclusion: [],
          exclusion: [],
          examples: [],
        },
      ],
    },
  };
  const app = defaultConfig();
  app.detectors.classifier = config;
  app.detectors.native.enabled = false;
  app.detectors.gitleaks.enabled = false;
  app.detectors.trufflehog.enabled = false;
  app.report.outputDir = path.join(directory, "report");
  const configPath = path.join(directory, "config.toml");
  fs.writeFileSync(configPath, stringify(app));
  return { config, configPath, root };
}

async function run(flags: string[], isTTY = false) {
  const f = fixture();
  let stdout = "",
    stderr = "";
  const errorStream = {
    isTTY,
    write(chunk: string) {
      stderr += chunk;
    },
  };
  const result = await runClearance({
    argv: ["--config", f.configPath, ...flags, f.root],
    env: {},
    stdout: { write: (chunk) => void (stdout += chunk) },
    stderr: errorStream,
  });
  const reports = ["manifest.json", "report.md", "report.html"].map((name) =>
    fs.readFileSync(path.join(path.dirname(f.configPath), "report", name), "utf8"),
  );
  return { result, stdout, stderr, reports };
}

describe("classifier progress metadata", () => {
  it("accepts only fixed stages, safe bounded counts, and exact metadata keys", () => {
    expect(classifierProgress(JSON.stringify(event()))).toEqual(event());
    expect(classifierProgress(JSON.stringify(event(16384, 16384)))).toEqual(event(16384, 16384));
    for (const invalid of [
      { ...event(), version: 2 },
      { ...event(), type: "diagnostic" },
      { ...event(), stage: privateDiagnostic },
      { ...event(), completed: -1 },
      { ...event(), completed: 3 },
      { ...event(), completed: 0.5 },
      { ...event(), total: 16385 },
      { ...event(), total: Number.MAX_SAFE_INTEGER + 1 },
      { ...event(), detail: privateDiagnostic },
      { ...event(), total: "2" },
      {},
      [],
      null,
    ])
      expect(classifierProgress(JSON.stringify(invalid))).toBeUndefined();
    expect(classifierProgress(privateDiagnostic)).toBeUndefined();
    expect(classifierProgress(JSON.stringify(event()) + " {} ")).toBeUndefined();
  });

  it("collects split and final unterminated records without exposing arbitrary stderr", async () => {
    const f = fixture();
    const records: ClassifierProgress[] = [];
    const output = await invokeClassifier(f.config, Buffer.from("{}"), {}, undefined, (record) =>
      records.push(record),
    );
    expect(records).toEqual([{ ...event(), stage: "planning" }, event(1), event(2)]);
    expect(JSON.stringify(records)).not.toContain(privateDiagnostic);
    expect(JSON.parse(output.toString()).status).toBe("complete");
  });

  it("bounds valid progress records independently of stderr diagnostics", async () => {
    const f = fixture("limit");
    const onProgress = vi.fn();
    await expect(
      invokeClassifier(f.config, Buffer.from("{}"), {}, undefined, onProgress),
    ).rejects.toThrow("stderr-limit");
    expect(onProgress).toHaveBeenCalledTimes(32770);
  });

  it("rejects oversized private diagnostics with a fixed error and no progress", async () => {
    const f = fixture("oversize");
    f.config.maxStderrBytes = 1024;
    const onProgress = vi.fn();
    await expect(
      invokeClassifier(f.config, Buffer.from("{}"), {}, undefined, onProgress),
    ).rejects.toThrow(/^stderr-limit$/);
    expect(onProgress).not.toHaveBeenCalled();
  });

  it("ignores a broken progress consumer without changing classifier output", async () => {
    const f = fixture();
    const output = await invokeClassifier(f.config, Buffer.from("{}"), {}, undefined, () => {
      throw new Error("display unavailable");
    });
    expect(JSON.parse(output.toString()).findings[0].text).toBe("secret");
    expect(() =>
      progressSink(true, {
        write() {
          throw new Error("closed stderr");
        },
      })("pipeline: preparing inventory"),
    ).not.toThrow();
  });
});

describe("CLI progress", () => {
  it.each(["complete", "trace-abort", "setup-abort"] as const)(
    "prints native hits, verdicts, and accurate abort notices (%s)",
    async (mode) => {
      const abort = mode === "trace-abort";
      const f = fixture();
      const tracePath = path.join(path.dirname(f.configPath), "trace.jsonl");
      if (abort) fs.writeFileSync(path.join(f.root, "second.txt"), "secret2");
      const rules = path.join(path.dirname(f.configPath), "rules");
      fs.mkdirSync(rules);
      fs.writeFileSync(
        path.join(rules, "rules.toml"),
        stringify({
          schema_version: "clearance-rules/1",
          rules: [
            {
              id: "fixture-secret",
              type: "regex",
              pattern: "secret[0-9]?",
              severity: "high",
              category: "credential",
            },
          ],
        }),
      );
      const app = defaultConfig();
      app.detectors.native.rulesD = rules;
      app.detectors.gitleaks.enabled = false;
      app.detectors.trufflehog.enabled = false;
      app.llm.enabled = true;
      app.llm.canOverride = true;
      app.llm.batch.maxClusters = 1;
      if (abort) app.llm.traceFile = tracePath;
      if (mode === "setup-abort")
        app.llm.instructions = path.join(path.dirname(f.configPath), "missing-instructions.txt");
      app.report.outputDir = path.join(path.dirname(f.configPath), "report");
      fs.writeFileSync(f.configPath, stringify(app));
      let stderr = "";
      let batches = 0;
      const result = await runClearance({
        argv: ["--config", f.configPath, "--progress", f.root],
        env: {},
        stdout: { write() {} },
        stderr: { write: (chunk) => void (stderr += chunk) },
        llmRuntime: {
          async validateBatch(request) {
            expect(stderr).toContain("finding [unverified]");
            expect(stderr).toContain('value="secret"');
            if (++batches === 2) {
              expect(stderr).toContain('confirmed: "reviewed"');
              fs.unlinkSync(tracePath);
              fs.mkdirSync(tracePath); // Later trace writes fail after a verdict streamed.
            }
            return {
              batchId: request.batchId,
              verdicts: request.clusters.map((cluster) => ({
                clusterId: cluster.clusterId,
                status: "confirmed",
                confidence: 1,
                rationale: "reviewed",
              })),
            };
          },
        },
      });
      if (mode === "setup-abort") {
        expect(result.llm?.status).toBe("failed");
        expect(stderr).toContain("LLM validation: aborted before any verdict");
        expect(stderr).not.toContain("discarded streamed verdicts");
        expect(batches).toBe(0);
        return;
      }
      if (abort) {
        expect(result.llm?.status).toBe("failed");
        expect(stderr).toContain("LLM validation: aborted; discarded streamed verdicts: 1");
        expect(result.clusters.every((cluster) => !cluster.llm)).toBe(true);
        return;
      }
      expect(result.llm?.status).toBe("complete");
      expect(result.outcome).toBe("denied");
      expect(stderr).toContain("pipeline: LLM finding validation");
      expect(stderr).toContain("LLM validation batch 1/1: starting");
      expect(stderr).toContain("LLM validation batch 1/1: completed");
      expect(stderr).toContain('value="secret"');
      expect(stderr).toContain('"private-filename.txt":1');
      expect(stderr).toContain("LLM verdict [pending final policy]");
      expect(stderr).toContain('confirmed: "reviewed"');
    },
  );

  it("keeps --json stdout valid while explicit progress appears only on stderr", async () => {
    const { result, stdout, stderr, reports } = await run(["--progress", "--json"]);
    expect(JSON.parse(stdout).outcome).toBe("denied");
    expect(result.outcome).toBe("denied");
    expect(stderr).toContain("pipeline: external classifier discovery");
    expect(stderr).toContain("classifier file 1/1: planning chunks");
    expect(stderr).toContain("classifier file 1/1: chunks 2/2");
    expect(stderr).toContain("pipeline: writing reports");
    for (const line of stderr.trimEnd().split("\n"))
      expect(line).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC \S/);
    expect(stderr).not.toContain("clearance:");
    expect(stderr).not.toContain(privateDiagnostic);
    expect(stderr).toContain('"private-filename.txt":1');
    expect(stderr).toContain('classifier/"classifier.confidential.private_fact"');
    expect(stderr).toContain('value="secret"');
    expect(stderr.indexOf('value="secret"')).toBeLessThan(
      stderr.indexOf("classifier file 1/1: completed"),
    );
    expect(stdout).not.toContain('"raw":"secret"');
    expect(JSON.parse(reports[0]!).clusters[0].raw).toBeUndefined();
    for (const report of reports) {
      expect(report).not.toContain('"raw": "secret"');
      expect(report).not.toContain(">secret<");
      expect(report).not.toContain("`secret`");
    }
  });

  it("makes --quiet suppress progress while retaining the same verdict", async () => {
    const noisy = await run(["--progress", "--json"]);
    const quiet = await run(["--quiet", "--json", "--include-raw"], true);
    expect(JSON.parse(quiet.reports[0]!).clusters[0].raw).toBe("secret");
    expect(quiet.stderr).toBe("");
    expect(quiet.result.outcome).toBe(noisy.result.outcome);
    expect(quiet.result.exitCode).toBe(noisy.result.exitCode);
    expect(quiet.result.occurrences.length).toBe(noisy.result.occurrences.length);
    expect(JSON.parse(quiet.stdout).outcome).toBe("denied");
  });

  it("defaults to silent progress on non-TTY stderr", async () => {
    const { stderr, result } = await run([]);
    expect(stderr).toBe("");
    expect(result.outcome).toBe("denied");
  });

  it("defaults to progress on TTY stderr for human output", async () => {
    const { stderr, result } = await run([], true);
    expect(stderr).toContain("pipeline: preparing inventory");
    expect(stderr).toContain("classifier file 1/1: completed");
    expect(stderr).toContain('value="secret"');
    expect(result.outcome).toBe("denied");
  });

  it("does not automatically add progress to --json even on TTY stderr", async () => {
    const { stdout, stderr } = await run(["--json"], true);
    expect(stderr).toBe("");
    expect(JSON.parse(stdout).outcome).toBe("denied");
  });
});
