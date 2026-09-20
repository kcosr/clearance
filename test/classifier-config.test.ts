import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stringify } from "smol-toml";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_CLASSIFIER, type ClassifierConfig } from "../src/classifier/config.js";
import { captureSnapshots, scanClassifier } from "../src/classifier/scanner.js";
import { parseArgs } from "../src/cli-parse.js";
import { loadConfig } from "../src/config.js";
import type { RootRecord } from "../src/types.js";
import type { ClassifiedFile } from "../src/walk.js";

const temporary: string[] = [];
afterEach(() => {
  for (const directory of temporary.splice(0))
    fs.rmSync(directory, { recursive: true, force: true });
});
function directory() {
  const result = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-classifier-config-"));
  temporary.push(result);
  return result;
}
describe("caller-selected classifier configuration", () => {
  it.each(["regular", "hardlink", "symlink"])(
    "accepts readable %s config without pins",
    async (kind) => {
      const dir = directory();
      const rootPath = path.join(dir, "input");
      fs.mkdirSync(rootPath);
      const root: RootRecord = {
        rootId: "root-1",
        supplied: rootPath,
        realPath: rootPath,
        git: { kind: "none" },
      };
      const absPath = path.join(rootPath, "input.txt");
      fs.writeFileSync(absPath, "secret");
      const stat = fs.statSync(absPath);
      const files: ClassifiedFile[] = [
        {
          rootId: root.rootId,
          relPosix: "input.txt",
          absPath,
          kind: "scannable",
          size: stat.size,
          mtimeMs: stat.mtimeMs,
        },
      ];
      const helper = path.join(dir, "helper.cjs");
      fs.writeFileSync(
        helper,
        `
const fs=require('node:fs');
if(process.argv[2]!=='--config')process.exit(8);
const settings=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',()=>{
 const request=JSON.parse(input);
 if(request.version!==4||Object.keys(request).sort().join()!=='policy,target,version')process.exit(8);
 process.stdout.write(JSON.stringify({version:2,status:'complete',findings:[{text:settings.finding,category:'credential',reason:'embedded_password'}]}));
});
`,
      );
      const original = path.join(dir, "config.json");
      fs.writeFileSync(original, JSON.stringify({ finding: "secret" }));
      fs.chmodSync(original, 0o644);
      const selected = kind === "regular" ? original : path.join(dir, "selected.json");
      if (kind === "hardlink") fs.linkSync(original, selected);
      if (kind === "symlink") fs.symlinkSync(original, selected);
      const config: ClassifierConfig = {
        ...structuredClone(DEFAULT_CLASSIFIER),
        enabled: true,
        executable: fs.realpathSync(process.execPath),
        args: [helper, "--config", selected],
        timeoutMs: 5000,
        policy: {
          instructions: "Find credentials.",
          categories: [
            {
              id: "credential",
              reasons: ["embedded_password"],
              severity: "high",
              inclusion: [],
              exclusion: [],
              examples: [],
            },
          ],
        },
      };
      const result = await scanClassifier({
        config,
        files,
        roots: [root],
        snapshots: captureSnapshots(files, [root], config),
        runKey: Buffer.alloc(32),
        env: {},
        maxTotalFindings: 100,
      });
      expect(result.detector.status).toBe("completed");
      expect(result.occurrences).toHaveLength(1);
      expect(result.occurrences[0]).toMatchObject({ path: "input.txt", candidate: "secret" });
    },
  );
});

describe("classifier configuration diagnostics", () => {
  it.each(["executableSha256", "configurationId", "pinnedFiles"])(
    "rejects obsolete %s configuration",
    (field) => {
      const dir = directory();
      const configPath = path.join(dir, "obsolete.toml");
      fs.writeFileSync(
        configPath,
        stringify({
          detectors: {
            classifier: { [field]: field === "pinnedFiles" ? [] : "sha256:" + "0".repeat(64) },
          },
        }),
      );
      expect(() =>
        loadConfig(parseArgs(["--config", configPath]), {}, path.join(dir, "no-system.toml")),
      ).toThrow();
    },
  );
  it("identifies missing executable and policy fields when --classifier enables empty defaults", () => {
    const missingSiteConfig = path.join(directory(), "no-system-config.toml");
    let message = "";
    try {
      loadConfig(parseArgs(["--classifier"]), {}, missingSiteConfig);
    } catch (error) {
      message = (error as Error).message;
    }
    for (const field of ["executable", "policy"])
      expect(message).toContain(`detectors.classifier.${field}`);
  });

  it("reports only schema-owned field names, never invalid values or unknown keys", () => {
    const dir = directory();
    const configPath = path.join(dir, "invalid.toml");
    const secret = "PRIVATE-INVALID-CONFIG-VALUE";
    fs.writeFileSync(
      configPath,
      stringify({
        detectors: {
          classifier: {
            timeoutMs: secret,
            policy: { categories: [{ id: secret, severity: secret }] },
            [secret]: secret,
          },
        },
      }),
    );
    let message = "";
    try {
      loadConfig(parseArgs(["--config", configPath]), {}, path.join(dir, "no-system.toml"));
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("detectors.classifier.timeoutMs");
    expect(message).toContain("detectors.classifier.policy");
    expect(message).not.toContain(secret);
    expect(message).not.toContain(configPath);
  });
});
