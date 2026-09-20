import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const executableName = process.platform === "win32" ? "clearance.exe" : "clearance";
const builtExecutable = path.join(root, "dist", executableName);
const isolatedDir = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-executable-"));
const nativeTarget = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-native-target-"));
const gitleaksTarget = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-gitleaks-target-"));
const classifierTarget = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-classifier-target-"));
const stdoutTarget = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-stdout-target-"));
const injectedOutput = path.join(os.tmpdir(), `clearance-injected-${process.pid}-${Date.now()}`);
const executable = path.join(isolatedDir, executableName);

function run(args: string[], cwd: string): ReturnType<typeof spawnSync> {
  return spawnSync(executable, args, { cwd, encoding: "utf8" });
}

try {
  fs.copyFileSync(builtExecutable, executable);
  fs.chmodSync(executable, 0o755);

  fs.writeFileSync(path.join(nativeTarget, ".env"), `CLEARANCE_OUTPUT=${injectedOutput}\n`);
  fs.writeFileSync(path.join(nativeTarget, "payload.exe"), "MZ fake executable\n");
  const native = run(["--no-gitleaks", "--no-trufflehog", "--json", "."], nativeTarget);
  assert.equal(native.status, 2, native.stderr || native.stdout);
  assert.equal(fs.existsSync(injectedOutput), false, "the scan root .env redirected output");
  const nativeManifest = JSON.parse(
    fs.readFileSync(path.join(nativeTarget, "clearance-report", "manifest.json"), "utf8"),
  ) as {
    detectors: Array<{ name: string; status: string }>;
    clusters: Array<{ category: string }>;
  };
  assert.equal(
    nativeManifest.detectors.find((detector) => detector.name === "native")?.status,
    "completed",
  );
  assert(nativeManifest.clusters.some((cluster) => cluster.category === "executable"));

  fs.writeFileSync(
    path.join(gitleaksTarget, "app.env"),
    "SLACK_BOT_TOKEN=xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx\n",
  );
  const gitleaks = run(
    ["--no-native", "--no-trufflehog", "--output", "report", "--json", "--progress", "."],
    gitleaksTarget,
  );
  assert.equal(gitleaks.status, 2, gitleaks.stderr || gitleaks.stdout);
  assert(gitleaks.stderr.includes("finding [unverified]"));
  assert(gitleaks.stderr.includes('"app.env":1'));
  assert(gitleaks.stderr.includes("gitleaks/"));
  assert.equal(JSON.parse(gitleaks.stdout).outcome, "denied");
  const gitleaksManifest = JSON.parse(
    fs.readFileSync(path.join(gitleaksTarget, "report", "manifest.json"), "utf8"),
  ) as {
    detectors: Array<{ name: string; status: string }>;
    clusters: Array<{ foundBy: string[] }>;
  };
  assert.equal(
    gitleaksManifest.detectors.find((detector) => detector.name === "gitleaks")?.status,
    "completed",
  );
  assert(gitleaksManifest.clusters.some((cluster) => cluster.foundBy.includes("gitleaks")));

  // Exercise the compiled caller with an ordinary executable/config boundary.
  const helper = path.join(isolatedDir, "classifier.cjs");
  const helperConfig = path.join(isolatedDir, "classifier.json");
  fs.writeFileSync(helperConfig, JSON.stringify({ text: "SYNTHETIC_CLASSIFIER_FACT" }));
  fs.chmodSync(helperConfig, 0o644);
  fs.writeFileSync(
    helper,
    `
const fs=require('node:fs');
if(process.argv[2]!=='--config'||process.argv.length!==4)process.exit(8);
const config=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',()=>{
 const request=JSON.parse(input);
 if(request.version!==4||Object.keys(request).sort().join()!=='policy,target,version'||request.target.kind!=='file'||request.target.path!=='input.txt')process.exit(8);
 process.stdout.write(JSON.stringify({version:2,status:'complete',findings:[{text:config.text,category:'business',reason:'confidential'}]}));
});
`,
  );
  fs.writeFileSync(path.join(classifierTarget, "input.txt"), "SYNTHETIC_CLASSIFIER_FACT\n");
  const classifierConfig = path.join(isolatedDir, "clearance-classifier.toml");
  fs.writeFileSync(
    classifierConfig,
    `
[detectors.native]
enabled=false
[detectors.gitleaks]
enabled=false
[detectors.trufflehog]
enabled=false
[detectors.classifier]
enabled=true
executable=${JSON.stringify(process.execPath)}
args=${JSON.stringify([helper, "--config", helperConfig])}
[detectors.classifier.policy]
instructions="Find the synthetic confidential fact."
[[detectors.classifier.policy.categories]]
id="business"
reasons=["confidential"]
severity="high"
`,
  );
  const classified = run(
    ["--config", classifierConfig, "--json", "--progress", "."],
    classifierTarget,
  );
  assert.equal(classified.status, 2, classified.stderr || classified.stdout);
  assert(classified.stderr.includes('value="SYNTHETIC_CLASSIFIER_FACT"'));
  assert(classified.stderr.includes("finding [unverified]"));
  assert(!classified.stdout.includes("SYNTHETIC_CLASSIFIER_FACT"));
  assert.equal(JSON.parse(classified.stdout).outcome, "denied");
  for (const name of ["manifest.json", "report.md", "report.html"])
    assert(
      !fs
        .readFileSync(path.join(classifierTarget, "clearance-report", name), "utf8")
        .includes("SYNTHETIC_CLASSIFIER_FACT"),
    );
  const classifierManifest = JSON.parse(
    fs.readFileSync(path.join(classifierTarget, "clearance-report/manifest.json"), "utf8"),
  );
  assert.equal(
    classifierManifest.detectors.find(
      (detector: { name: string }) => detector.name === "classifier",
    )?.status,
    "completed",
  );
  assert(
    classifierManifest.clusters.some((cluster: { foundBy: string[] }) =>
      cluster.foundBy.includes("classifier"),
    ),
  );
  assert(!("configurationId" in classifierManifest.classifier));

  fs.rmSync(path.join(classifierTarget, "clearance-report"), { recursive: true });
  const stdoutOnly = run(
    ["--config", classifierConfig, "--json", "--no-report", "--quiet", "--include-raw", "."],
    classifierTarget,
  );
  assert.equal(stdoutOnly.status, 2, stdoutOnly.stderr);
  assert.equal(stdoutOnly.stderr, "");
  const full = JSON.parse(stdoutOnly.stdout);
  assert.equal(full.clusters[0].raw, "SYNTHETIC_CLASSIFIER_FACT");
  assert.equal(full.classifier.files[0].status, "completed");
  assert(!fs.existsSync(path.join(classifierTarget, "clearance-report")));

  // JSON now contains every finding; verify the compiled CLI flushes a pipe
  // larger than its buffer before exiting, without producing report files.
  for (let n = 0; n < 300; n++)
    fs.writeFileSync(path.join(stdoutTarget, `payload-${n}.exe`), "MZ synthetic\n");
  const large = run(
    ["--no-report", "--json", "--quiet", "--no-gitleaks", "--no-trufflehog", "."],
    stdoutTarget,
  );
  assert.equal(large.status, 2, large.stderr);
  assert.equal(large.stderr, "");
  assert(large.stdout.length > 65536);
  assert(JSON.parse(large.stdout).occurrences.length >= 300);
  assert.equal(fs.readdirSync(stdoutTarget).length, 300);
  console.log("standalone executable checks passed");
} finally {
  for (const target of [
    isolatedDir,
    nativeTarget,
    gitleaksTarget,
    classifierTarget,
    stdoutTarget,
    injectedOutput,
  ]) {
    fs.rmSync(target, { recursive: true, force: true });
  }
}
