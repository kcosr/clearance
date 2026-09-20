import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stringify } from "smol-toml";
import { DEFAULT_CLASSIFIER, type ClassifierConfig } from "../src/classifier/config.js";
import { invokeClassifier } from "../src/classifier/process.js";
import { response } from "../src/classifier/protocol.js";
import { captureSnapshots, scanClassifier, verifySnapshots } from "../src/classifier/scanner.js";
import { defaultConfig } from "../src/config.js";
import { runClearance } from "../src/scan.js";
import type { RootRecord } from "../src/types.js";
import type { BatchRequest } from "../src/llm/schema.js";
import type { ClassifiedFile } from "../src/walk.js";

const executable = fs.realpathSync(process.execPath);
const finding = { text: "secret", category: "confidential", reason: "private_fact" };
const envelope = (findings: unknown[] = [finding]) => ({
  version: 2,
  status: "complete",
  findings,
});
const temporary: string[] = [];
afterEach(() => {
  for (const dir of temporary.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

// A deterministic executable adapter. No model or external detector runs.
const script = `
const fs=require('node:fs');
const mode=process.argv[2];
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',s=>input+=s);
process.stdin.on('end',()=>{
 const request=JSON.parse(input);
 if(request.version!==4||request.target.kind!=='file'||!request.target.path||Object.keys(request.target).sort().join()!=='kind,path,text')process.exit(8);
 const text=request.target.text;
 const fact=(text)=>({text,category:'confidential',reason:'private_fact'});
 let result={version:2,status:'complete',findings:[fact('secret')]};
 if(mode==='file-shape'){
  if(request.target.path!==process.argv[3]||text!==process.argv[4])process.exit(8);
 }
 if(mode==='clean')result.findings=[];
 if(mode==='unicode')result.findings=[fact('😀é'),fact('aba')];
 if(mode==='invented')result.findings=[fact('not present')];
 if(mode==='vocabulary')result.findings[0].category='unknown';
 if(mode==='obsolete')result.configuration_id='sha256:'+'2'.repeat(64);
 if(mode==='duplicate'){process.stdout.write(JSON.stringify(result).replace('"version":2','"version":2,"version":2'));return;}
 if(mode==='trailing'){process.stdout.write(JSON.stringify(result)+' {}');return;}
 if(mode==='malformed'){process.stdout.write('{');return;}
 if(mode==='output'){process.stdout.write('x'.repeat(10000));return;}
 if(mode==='stderr'){process.stderr.write('x'.repeat(10000));return;}
 if(mode==='exit'){process.stdout.write(JSON.stringify(result));process.exitCode=9;return;}
 if(mode==='hang'){if(process.argv[3])fs.writeFileSync(process.argv[3],String(process.pid));setInterval(()=>{},1000);return;}
 if(mode==='raw'){
  if(text!=='KNOWN secret KNOWN'||request.target.path!=='input.txt')process.exit(8);
  result.findings=[fact('secret')];
 }
 if(mode==='label')result.findings=[fact('[REDACTED]')];
 if(mode==='cross-mask')result.findings=[fact('beforeafter')];
 if((mode==='partial'||mode==='partial-clean')&&text.includes('FAIL')){process.exitCode=7;return;}
 if(mode==='partial-clean')result.findings=[];
 if(mode==='distinct')result.findings=[...new Set(text.match(/PRIVATE_FACT_[0-9]+/g)||[])].map(fact);
 if(mode==='drift')fs.writeFileSync(process.argv[3],'mutated contents');
 if(mode==='environment'){
  if(process.env.EXPLICIT!=='allowed'||process.env.UNLISTED!==undefined)process.exit(8);
  result.findings=[];
 }
 process.stdout.write(JSON.stringify(result)+'\\n');
});
`;

function fixture(contents: Record<string, string> = { "input.txt": "secret" }, mode = "success") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-classifier-"));
  temporary.push(dir);
  const rootPath = path.join(dir, "input");
  fs.mkdirSync(rootPath);
  const helper = path.join(dir, "helper.cjs");
  fs.writeFileSync(helper, script);
  const config: ClassifierConfig = {
    ...structuredClone(DEFAULT_CLASSIFIER),
    enabled: true,
    executable,
    args: [helper, mode],
    timeoutMs: 2000,
    policy: {
      instructions: "Find private facts.",
      categories: [
        {
          id: "confidential",
          reasons: ["private_fact"],
          inclusion: [],
          exclusion: [],
          examples: [],
          severity: "high",
        },
      ],
    },
  };
  const root: RootRecord = {
    rootId: "root-1",
    supplied: rootPath,
    realPath: rootPath,
    git: { kind: "none", reason: "not-a-git-repository" },
  };
  const files: ClassifiedFile[] = Object.entries(contents).map(([relPosix, text]) => {
    const absPath = path.join(rootPath, relPosix);
    fs.writeFileSync(absPath, text);
    const stat = fs.statSync(absPath);
    return {
      rootId: root.rootId,
      relPosix,
      absPath,
      kind: "scannable",
      size: stat.size,
      mtimeMs: stat.mtimeMs,
    };
  });
  const snapshots = captureSnapshots(files, [root], config);
  const scan = (signal?: AbortSignal) =>
    scanClassifier({
      config,
      files,
      roots: [root],
      snapshots,
      runKey: Buffer.alloc(32, 7),
      env: { PARENT_VALUE: "allowed", UNLISTED: "must not inherit" },
      maxTotalFindings: 10000,
      ...(signal ? { signal } : {}),
    });
  return { dir, root, files, helper, config, snapshots, scan };
}
const input = Buffer.from(
  JSON.stringify({
    version: 4,
    target: { kind: "file", path: "example.txt", text: "secret" },
  }),
);

describe("external classifier discovery", () => {
  it("discovers in deterministic-clean content and skips direct LLM confirmation", async () => {
    const f = fixture();
    const app = defaultConfig();
    app.detectors.classifier = f.config;
    app.detectors.native.enabled = false;
    app.detectors.gitleaks.enabled = false;
    app.detectors.trufflehog.enabled = false;
    app.llm.enabled = true;
    app.report.outputDir = path.join(f.dir, "report");
    const configPath = path.join(f.dir, "config.toml");
    fs.writeFileSync(configPath, stringify(app));
    const validateBatch = vi.fn(async () => {
      throw new Error("discovery must not be confirmed again");
    });
    const result = await runClearance({
      argv: ["--config", configPath, f.root.realPath],
      env: {},
      stdout: { write() {} },
      stderr: { write() {} },
      llmRuntime: { validateBatch },
    });
    expect(result.outcome).toBe("denied");
    expect(result.occurrences).toHaveLength(1);
    expect(result.occurrences[0]?.scanner).toBe("classifier");
    expect(validateBatch).not.toHaveBeenCalled();
    const manifest = JSON.parse(
      fs.readFileSync(path.join(f.dir, "report", "manifest.json"), "utf8"),
    );
    expect(manifest.occurrences[0]).not.toHaveProperty("candidate");
    expect(manifest.occurrences[0]).not.toHaveProperty("evidenceText");
    expect(manifest.clusters[0]).not.toHaveProperty("raw");
    for (const name of ["manifest.json", "report.md", "report.html"])
      expect(fs.existsSync(path.join(f.dir, "report", name))).toBe(true);
  });
  it("maps repeated Unicode and overlapping occurrences to original UTF-8 offsets", async () => {
    const text = "Z😀é ababa\n😀é";
    const f = fixture({ "input.txt": text }, "unicode");
    const result = await f.scan();
    expect(result.detector.status).toBe("completed");
    expect(result.occurrences).toHaveLength(4);
    expect(result.occurrences.map((o) => [o.byteStart, o.byteEnd])).toEqual([
      [1, 7],
      [8, 11],
      [10, 13],
      [14, 20],
    ]);
    for (const occ of result.occurrences)
      expect(Buffer.from(text).subarray(occ.byteStart, occ.byteEnd).toString()).toBe(occ.candidate);
  });
  it("keeps test fixtures in classifier input when excluding them from the outcome", async () => {
    const f = fixture({ "auth.test.ts": "secret", "production.ts": "secret" });
    const app = defaultConfig();
    app.detectors.classifier = f.config;
    app.detectors.native.enabled = false;
    app.detectors.gitleaks.enabled = false;
    app.detectors.trufflehog.enabled = false;
    app.report.outputDir = path.join(f.dir, "report");
    const configPath = path.join(f.dir, "config.toml");
    fs.writeFileSync(configPath, stringify(app));
    const run = (extra: string[]) =>
      runClearance({
        argv: ["--config", configPath, ...extra, f.root.realPath],
        env: {},
        stdout: { write() {} },
        stderr: { write() {} },
      });
    const normal = await run([]);
    expect(normal.occurrences.map((o) => o.path).sort()).toEqual(["auth.test.ts", "production.ts"]);
    const skipped = await run(["--exclude-test-fixtures"]);
    expect(skipped.occurrences.map((o) => o.path).sort()).toEqual([
      "auth.test.ts",
      "production.ts",
    ]);
    expect(skipped.classifier?.files).toContainEqual({
      rootId: "root-1",
      path: "auth.test.ts",
      status: "completed",
    });
    expect(skipped.coverage).toEqual([]);
  });
  it.each([
    ["backslash", "folder\\name.txt"],
    ["ZWJ", "developer-👩‍💻.txt"],
    ["newline", "line\nbreak.txt"],
    ["colon", "t:notes.txt"],
  ])(
    "preserves legal POSIX %s filenames and original text in the v4 request",
    async (_label, name) => {
      const text = 'Original secret with "quotes", a backslash \\ and a newline.\nSecond line.\n';
      const f = fixture({ [name!]: text }, "file-shape");
      f.config.args.push(name!, text);
      const app = defaultConfig();
      app.detectors.classifier = f.config;
      app.detectors.native.enabled = false;
      app.detectors.gitleaks.enabled = false;
      app.detectors.trufflehog.enabled = false;
      app.report.outputDir = path.join(f.dir, "report");
      const configPath = path.join(f.dir, "config.toml");
      fs.writeFileSync(configPath, stringify(app));
      const result = await runClearance({
        argv: ["--config", configPath, f.root.realPath],
        env: {},
        stdout: { write() {} },
        stderr: { write() {} },
      });
      expect(result.detectors.find((d) => d.name === "classifier")?.status).toBe("completed");
      expect(result.classifier?.files).toEqual([
        { rootId: "root-1", path: name, status: "completed" },
      ]);
      expect(result.occurrences).toHaveLength(1);
      expect(result.occurrences[0]).toMatchObject({
        path: name,
        candidate: "secret",
        byteStart: 9,
        byteEnd: 15,
      });
      expect(result.coverage).toEqual([]);
    },
  );
  it("sends the original file with its relative path", async () => {
    const f = fixture({ "input.txt": "KNOWN secret KNOWN" }, "raw");
    const result = await f.scan();
    expect(result.detector.status).toBe("completed");
    expect(result.occurrences[0]?.byteStart).toBe(6);
  });
  it.each(["label", "cross-mask"])("rejects invented %s findings", async (mode) => {
    const f = fixture({ "input.txt": "beforeKNOWNafter" }, mode);
    const result = await f.scan();
    expect(result.coverage[0]?.reason).toBe("invalid-source");
    expect(result.occurrences).toHaveLength(0);
  });
  it("completes empty files locally", async () => {
    const f = fixture({ "empty.txt": "" }, "exit");
    const result = await f.scan();
    expect(result.detector.status).toBe("completed");
    expect(result.coverage[0]?.status).toBe("empty");
  });
  it.each(["invented", "vocabulary", "obsolete", "duplicate", "trailing", "malformed"])(
    "rejects %s output without findings",
    async (mode) => {
      const f = fixture(undefined, mode);
      const result = await f.scan();
      expect(result.detector.status).toBe("partial");
      expect(result.occurrences).toEqual([]);
      expect(result.coverage[0]?.status).toBe("failed");
    },
  );
  it("preserves completed findings when another file fails", async () => {
    const f = fixture({ "good.txt": "secret", "bad.txt": "FAIL" }, "partial");
    const result = await f.scan();
    expect(result.detector.status).toBe("partial");
    expect(result.occurrences.map((o) => o.path)).toEqual(["good.txt"]);
    expect(result.coverage.map((c) => c.status).sort()).toEqual(["completed", "failed"]);
  });
  it("detects mutation before invocation and after successful response", async () => {
    const before = fixture();
    fs.writeFileSync(before.files[0]!.absPath, "change");
    expect((await before.scan()).coverage[0]?.reason).toBe("drift");
    const after = fixture(undefined, "drift");
    after.config.args.push(after.files[0]!.absPath);
    const result = await after.scan();
    expect(result.coverage[0]?.reason).toBe("drift");
    expect(result.occurrences).toEqual([]);
  });
  it("final digest verification catches same-size changed content", async () => {
    const f = fixture();
    const result = await f.scan();
    const stat = fs.statSync(f.files[0]!.absPath);
    fs.writeFileSync(f.files[0]!.absPath, "SECRET");
    fs.utimesSync(f.files[0]!.absPath, stat.atime, stat.mtime);
    verifySnapshots(f.files, [f.root], f.snapshots, f.config, result.coverage);
    expect(result.coverage[0]?.reason).toBe("drift");
  });
  it("passes only explicit environment and reports missing mappings", async () => {
    const f = fixture(undefined, "environment");
    f.config.env = { EXPLICIT: "PARENT_VALUE" };
    expect((await f.scan()).detector.status).toBe("completed");
    f.config.env = { EXPLICIT: "MISSING" };
    const result = await f.scan();
    expect(result.detector.status).toBe("failed");
    expect(result.coverage[0]?.reason).toBe("environment-unavailable");
  });
  it("bounds occurrence expansion and refuses malformed UTF-8", async () => {
    const limited = fixture({ "input.txt": "secret secret" });
    limited.config.maxFindings = 1;
    expect((await limited.scan()).coverage[0]?.reason).toBe("finding-limit");
    const invalid = fixture();
    fs.writeFileSync(invalid.files[0]!.absPath, Buffer.from([0xff]));
    const snapshots = captureSnapshots(invalid.files, [invalid.root], invalid.config);
    const result = await scanClassifier({
      config: invalid.config,
      files: invalid.files,
      roots: [invalid.root],
      snapshots,
      runKey: Buffer.alloc(32),
      env: {},
      maxTotalFindings: 10000,
    });
    expect(result.detector.status).toBe("partial");
    expect(result.coverage[0]?.reason).toBe("invalid-utf8");
    expect(result.occurrences).toEqual([]);
  });
  it("propagates partial discovery failure into a non-clean CLI outcome", async () => {
    const f = fixture({ "good.txt": "secret", "bad.txt": "FAIL" }, "partial");
    const app = defaultConfig();
    app.detectors.classifier = f.config;
    app.detectors.native.enabled = false;
    app.detectors.gitleaks.enabled = false;
    app.detectors.trufflehog.enabled = false;
    app.report.outputDir = path.join(f.dir, "report");
    const configPath = path.join(f.dir, "config.toml");
    fs.writeFileSync(configPath, stringify(app));
    const result = await runClearance({
      argv: ["--config", configPath, f.root.realPath],
      env: {},
      stdout: { write() {} },
      stderr: { write() {} },
    });
    expect(result.outcome).toBe("denied");
    expect(result.exitCode).toBe(2);
    expect(result.occurrences.map((o) => o.path)).toEqual(["good.txt"]);
    expect(
      result.coverage.some((c) => c.path === "bad.txt" && c.reason === "classifier-incomplete"),
    ).toBe(true);
  });
  it("resolves fifty distinct repeatedly occurring findings in a 1 MiB file under default budgets", async () => {
    const facts = Array.from(
      { length: 50 },
      (_, i) => `PRIVATE_FACT_${String(i).padStart(3, "0")}`,
    );
    const prefix = (facts.join("\n") + "\n").repeat(20);
    const text = prefix + ".".repeat(1024 * 1024 - prefix.length);
    const f = fixture({ "input.txt": text }, "distinct");
    const result = await f.scan();
    expect(f.config.maxResolutionBytes).toBe(DEFAULT_CLASSIFIER.maxResolutionBytes);
    expect(result.detector.status).toBe("completed");
    expect(result.occurrences).toHaveLength(1000);
    const bytes = Buffer.from(text);
    for (const fact of facts)
      expect(result.occurrences.filter((o) => o.candidate === fact)).toHaveLength(20);
    for (const occurrence of result.occurrences)
      expect(bytes.subarray(occurrence.byteStart, occurrence.byteEnd).toString()).toBe(
        occurrence.candidate,
      );
  });

  it.each([
    [1000, 1],
    [4096, 8],
  ])("resolves %i distinct findings in %i MiB under default budgets", async (count, mib) => {
    const facts = Array.from(
      { length: count! },
      (_, i) => `PRIVATE_FACT_${String(i).padStart(4, "0")}`,
    );
    const prefix = facts.join("\n") + "\n";
    const text = prefix + ".".repeat(mib! * 1024 * 1024 - prefix.length);
    const f = fixture({ "input.txt": text }, "distinct");
    const result = await f.scan();
    expect(result.detector.status).toBe("completed");
    expect(result.occurrences).toHaveLength(count!);
    const bytes = Buffer.from(text);
    for (const occurrence of result.occurrences)
      expect(bytes.subarray(occurrence.byteStart, occurrence.byteEnd).toString()).toBe(
        occurrence.candidate,
      );
  });

  it.each([false, true])(
    "partial discovery gives incomplete exit 2 and still validates native findings: %s",
    async (withNative) => {
      const f = fixture(
        { "good.txt": withNative ? "NATIVE_FACT ordinary" : "ordinary", "bad.txt": "FAIL" },
        "partial-clean",
      );
      const app = defaultConfig();
      app.detectors.classifier = f.config;
      app.detectors.native.enabled = withNative;
      app.detectors.gitleaks.enabled = false;
      app.detectors.trufflehog.enabled = false;
      app.report.outputDir = path.join(f.dir, "report");
      app.llm.enabled = withNative;
      if (withNative) {
        const rules = path.join(f.dir, "rules");
        fs.mkdirSync(rules);
        fs.writeFileSync(
          path.join(rules, "native.toml"),
          stringify({
            rules: [
              {
                id: "native-fact",
                type: "regex",
                pattern: "NATIVE_FACT",
                category: "confidential",
                severity: "low",
              },
            ],
          }),
        );
        app.detectors.native.rulesD = rules;
      }
      const configPath = path.join(f.dir, "config.toml");
      fs.writeFileSync(configPath, stringify(app));
      const validateBatch = vi.fn(async (request: BatchRequest) => ({
        batchId: request.batchId,
        verdicts: request.clusters.map((cluster) => ({
          clusterId: cluster.clusterId,
          status: "confirmed" as const,
          confidence: 1,
          rationale: "Confirmed local finding.",
        })),
      }));
      const result = await runClearance({
        argv: ["--config", configPath, f.root.realPath],
        env: {},
        stdout: { write() {} },
        stderr: { write() {} },
        llmRuntime: { validateBatch },
      });
      expect(result.outcome).toBe("incomplete");
      expect(result.exitCode).toBe(2);
      expect(result.detectors.find((d) => d.name === "classifier")?.status).toBe("partial");
      expect(
        result.coverage.some((c) => c.path === "bad.txt" && c.reason === "classifier-incomplete"),
      ).toBe(true);
      expect(validateBatch).toHaveBeenCalledTimes(withNative ? 1 : 0);
      if (withNative) {
        expect(result.occurrences[0]?.scanner).toBe("native");
        expect(result.clusters[0]?.llm?.status).toBe("confirmed");
      }
    },
  );
});

describe("external classifier process limits", () => {
  it.each([
    ["output", "output-limit"],
    ["stderr", "stderr-limit"],
    ["exit", "process-failed"],
    ["hang", "timeout"],
  ])("bounds %s and reaps the child", async (mode, reason) => {
    const f = fixture(undefined, mode);
    f.config.maxOutputBytes = 500;
    f.config.maxStderrBytes = 500;
    f.config.timeoutMs = mode === "hang" ? 150 : 2000;
    await expect(invokeClassifier(f.config, input, {})).rejects.toThrow(reason);
  });
  it("cancels running children and returns only after they exit", async () => {
    const f = fixture(undefined, "hang");
    const pidfile = path.join(f.dir, "pid");
    f.config.args.push(pidfile);
    const control = new AbortController();
    const run = invokeClassifier(f.config, input, {}, control.signal);
    const assertion = expect(run).rejects.toThrow("cancelled");
    await vi.waitFor(() => expect(fs.existsSync(pidfile)).toBe(true), {
      timeout: 1500,
      interval: 10,
    });
    const pid = Number(fs.readFileSync(pidfile, "utf8"));
    control.abort();
    await assertion;
    expect(() => process.kill(pid, 0)).toThrow();
  });
  it("rejects pre-cancelled and oversized requests", async () => {
    const f = fixture();
    const control = new AbortController();
    control.abort();
    await expect(invokeClassifier(f.config, input, {}, control.signal)).rejects.toThrow(
      "cancelled",
    );
    f.config.maxInputBytes = 1;
    await expect(invokeClassifier(f.config, input, {})).rejects.toThrow("input-limit");
  });
});

describe("strict external response", () => {
  it.each([
    '{"version":1,"ver\\u0073ion":1}',
    JSON.stringify(envelope()) + " {}",
    JSON.stringify({ ...envelope(), version: 1 }),
    JSON.stringify({ ...envelope(), extra: true }),
    '"\\ud800"',
  ])("rejects malformed/ambiguous JSON %s", (wire) => {
    expect(() => response(Buffer.from(wire), 20, 1000)).toThrow();
  });
  it("enforces finding count and UTF-8 byte bounds", () => {
    expect(() => response(Buffer.from(JSON.stringify(envelope())), 0, 1000)).toThrow();
    expect(() =>
      response(Buffer.from(JSON.stringify(envelope([{ ...finding, text: "😀" }]))), 20, 3),
    ).toThrow();
  });
});
