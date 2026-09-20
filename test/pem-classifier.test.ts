import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { stringify } from "smol-toml";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_CLASSIFIER } from "../src/classifier/config.js";
import { clusterOccurrences } from "../src/cluster.js";
import { defaultConfig } from "../src/config.js";
import { extractEvidence, extractPemPrivateKeyBlock } from "../src/evidence.js";
import { runClearance } from "../src/scan.js";
import { publicOccurrence } from "../src/report/public.js";
import { applySuppressions } from "../src/suppress.js";
import type { Occurrence, RootRecord } from "../src/types.js";

const begin = `-----BEGIN ${"RSA PRIVATE KEY"}-----`;
const end = `-----END ${"RSA PRIVATE KEY"}-----`;
const keyBody = "QUJDREVGR0g="; // Synthetic test payload, not a real key.
const canonical = [begin, keyBody, end].join("\n");
const executable = fs.realpathSync(process.execPath);
const temporary: string[] = [];
afterEach(() => {
  for (const directory of temporary.splice(0))
    fs.rmSync(directory, { recursive: true, force: true });
});

const formats = [
  { name: "plain LF", cr: "", indent: "", trailing: "" },
  { name: "CRLF", cr: "\r", indent: "", trailing: "" },
  { name: "indented LF", cr: "", indent: "  \t", trailing: "" },
  { name: "trailing whitespace", cr: "", indent: "", trailing: " \t" },
  { name: "indented CRLF with whitespace", cr: "\r", indent: "  ", trailing: "\t " },
];

function content(format: (typeof formats)[number]) {
  const line = (value: string) => `${format.indent}${value}${format.trailing}${format.cr}`;
  // The LF separator is restored verbatim; CR remains part of its original line.
  const block = [begin, keyBody, end].map(line).join("\n");
  const text = `public introduction${format.cr}\n${block}\npublic ending`;
  return { block, text };
}

function fixture(text: string) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-pem-classifier-"));
  temporary.push(directory);
  const rootPath = path.join(directory, "input");
  fs.mkdirSync(rootPath);
  fs.writeFileSync(path.join(rootPath, "source.txt"), text);
  const root: RootRecord = {
    rootId: "root-1",
    supplied: rootPath,
    realPath: rootPath,
    git: { kind: "none" },
  };
  return { directory, root };
}

function nativeHeader(root: RootRecord): Occurrence {
  return {
    occurrenceId: "pem-header",
    scanner: "native",
    rootId: root.rootId,
    path: "source.txt",
    lineStart: 2,
    lineEnd: 2,
    ruleId: "private-key",
    category: "private-key",
    severity: "critical",
    source: { kind: "workingTree" },
    extraction: "exact",
    candidate: begin,
  };
}

describe("exact PEM evidence", () => {
  it.each(formats)("preserves $name in the complete extracted source substring", (format) => {
    const { block, text } = content(format);
    expect(extractPemPrivateKeyBlock(text.split("\n"), 2, 2)).toBe(block);
    const f = fixture(text);
    const evidence = extractEvidence(
      nativeHeader(f.root),
      f.root,
      defaultConfig(),
      Buffer.alloc(32),
    );
    expect(evidence.extraction).toBe("exact");
    expect(evidence.candidate).toBe(canonical);
    expect(evidence.candidateFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(publicOccurrence(evidence))).not.toContain(keyBody);
  });

  it("uses one canonical identity and allowlist across all source layouts", () => {
    const config = defaultConfig();
    config.suppress.strings = [canonical];
    const occurrences = formats.map((format, index) => {
      const f = fixture(content(format).text);
      return extractEvidence(
        { ...nativeHeader(f.root), occurrenceId: `pem-${index}` },
        f.root,
        config,
        Buffer.alloc(32),
      );
    });
    expect(new Set(occurrences.map((occurrence) => occurrence.candidateFingerprint)).size).toBe(1);
    const suppressed = applySuppressions(occurrences, clusterOccurrences(occurrences, []), config);
    expect(suppressed.occurrences.every((occurrence) => occurrence.suppressed)).toBe(true);
    expect(suppressed.clusters.every((cluster) => cluster.effectiveStatus === "suppressed")).toBe(
      true,
    );
  });

  it("correlates a canonical historical key with its reformatted working-tree copy", () => {
    const original = content(formats[0]!).text;
    const current = content(formats[formats.length - 1]!).text;
    const f = fixture(original);
    const git = (...args: string[]) =>
      execFileSync("git", ["-C", f.root.realPath, "-c", "core.hooksPath=/dev/null", ...args], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    git("init", "--quiet");
    git("add", "source.txt");
    git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "--quiet",
      "-m",
      "fixture",
    );
    const commit = git("rev-parse", "HEAD");
    fs.writeFileSync(path.join(f.root.realPath, "source.txt"), current);
    f.root.git = { kind: "worktree", topLevel: f.root.realPath };
    const config = defaultConfig();
    const historical = extractEvidence(
      {
        ...nativeHeader(f.root),
        occurrenceId: "historical",
        scanner: "gitleaks",
        source: { kind: "git", commit },
      },
      f.root,
      config,
      Buffer.alloc(32),
    );
    const working = extractEvidence(nativeHeader(f.root), f.root, config, Buffer.alloc(32));
    expect(historical.candidateFingerprint).toBe(working.candidateFingerprint);
    const clusters = clusterOccurrences([historical, working], []);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]).toMatchObject({
      presence: "current_and_historical",
      foundBy: ["gitleaks", "native"],
      candidate: canonical,
    });
  });

  it("preserves mixed line endings and a closing marker at EOF", () => {
    const block = `${begin} \r\n\t${keyBody}\n${end}\t`;
    const text = `prefix\n${block}`;
    expect(extractPemPrivateKeyBlock(text.split("\n"), 2, 2)).toBe(block);
  });

  const screeningCases = formats.map((format) => ({
    name: format.name,
    text: content(format).text,
    blocks: [content(format).block],
  }));
  screeningCases.push({
    name: "repeated keys with different layouts",
    text: formats.map((format) => content(format).text).join("\n"),
    blocks: formats.map((format) => content(format).block),
  });

  it.each(screeningCases)(
    "sends the original $name content, including detected keys, to the classifier",
    async ({ text, blocks }) => {
      const f = fixture(text);
      const helper = path.join(f.directory, "helper.cjs");
      const script = `
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',()=>{
 const request=JSON.parse(input);
 const source=request.target.text;
 if(source!==${JSON.stringify(text)})process.exit(9);
 if(!source.includes('public introduction')||!source.includes('public ending'))process.exit(8);
 process.stdout.write(JSON.stringify({version:2,status:'complete',findings:[]}));
});
`;
      fs.writeFileSync(helper, script);
      const config = defaultConfig();
      config.detectors.gitleaks.enabled = false;
      config.detectors.trufflehog.enabled = false;
      config.report.outputDir = path.join(f.directory, "report");
      config.detectors.classifier = {
        ...structuredClone(DEFAULT_CLASSIFIER),
        enabled: true,
        executable,
        args: [helper],
        timeoutMs: 5000,
        policy: {
          instructions: "Find additional credentials.",
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
      const configPath = path.join(f.directory, "config.toml");
      fs.writeFileSync(configPath, stringify(config));
      const result = await runClearance({
        argv: ["--config", configPath, f.root.realPath],
        env: {},
        stdout: { write() {} },
        stderr: { write() {} },
      });
      expect(result.detectors.find((detector) => detector.name === "classifier")?.status).toBe(
        "completed",
      );
      expect(result.classifier?.files).toEqual([
        expect.objectContaining({ path: "source.txt", status: "completed" }),
      ]);
      const native = result.occurrences.filter((occurrence) => occurrence.scanner === "native");
      expect(native.map((occurrence) => occurrence.candidate)).toEqual(blocks.map(() => canonical));
      for (const filename of ["manifest.json", "report.md", "report.html"]) {
        const report = fs.readFileSync(path.join(config.report.outputDir, filename), "utf8");
        expect(report).not.toContain(keyBody);
      }
      expect(result.coverage).toHaveLength(0);
      expect(result.outcome).toBe("denied"); // The deterministic key finding still applies.
    },
  );
});
