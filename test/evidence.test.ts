import { describe, expect, it } from "vitest";
import { clusterOccurrences } from "../src/cluster.js";
import { defaultConfig } from "../src/config.js";
import {
  extractEvidence,
  extractPemPrivateKeyBlock,
  extractTokenFromLine,
  sliceLineColumns,
} from "../src/evidence.js";
import { newRunKey } from "../src/ids.js";
import type { Occurrence, ScannerName } from "../src/types.js";
import { resolveRoots } from "../src/walk.js";
import { SLACK_LINE, SLACK_TOKEN, tempDir, writeTree } from "./helpers.js";

const PEM_A = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "QUJDREVGR0g=",
  "-----END RSA PRIVATE KEY-----",
].join("\n");
const PEM_B = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "SUprTE1OT1A=",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

function privateKeyOccurrence(scanner: ScannerName, rootId: string, path: string): Occurrence {
  return {
    occurrenceId: `o-${scanner}-${path}`,
    scanner,
    rootId,
    path,
    lineStart: 1,
    lineEnd: scanner === "gitleaks" ? 3 : 1,
    ...(scanner === "gitleaks" ? { columnStart: 1, columnEnd: 30 } : {}),
    ruleId: "private-key",
    category: "private-key",
    severity: "critical",
    source: { kind: "workingTree" },
    extraction: scanner === "native" ? "exact" : "inexact",
    ...(scanner === "native" ? { candidate: "-----BEGIN RSA PRIVATE KEY-----" } : {}),
  };
}

describe("evidence", () => {
  it("slices gitleaks columns into an exact token", () => {
    const line = SLACK_LINE.trimEnd();
    const start = line.indexOf(SLACK_TOKEN) + 1;
    const end = start + SLACK_TOKEN.length - 1;
    expect(sliceLineColumns(line, start, end)).toBe(SLACK_TOKEN);
  });

  it("extracts slack and stripe tokens from a trufflehog line and leaves passwords inexact", () => {
    expect(extractTokenFromLine(SLACK_LINE)).toBe(SLACK_TOKEN);
    expect(extractTokenFromLine("password=hunter2")).toBeUndefined();
  });

  it("fingerprints exact native matches from the working tree", () => {
    const rootDir = tempDir("clearance-ev-");
    writeTree(rootDir, { "app.env": SLACK_LINE });
    const [root] = resolveRoots([rootDir]);
    const next = extractEvidence(
      {
        occurrenceId: "o1",
        scanner: "trufflehog",
        rootId: root!.rootId,
        path: "app.env",
        lineStart: 1,
        lineEnd: 1,
        ruleId: "Slack",
        category: "slack-token",
        severity: "high",
        source: { kind: "workingTree" },
        extraction: "inexact",
      },
      root!,
      defaultConfig(),
      newRunKey(),
    );
    expect(next.extraction).toBe("exact");
    expect(next.candidate).toBe(SLACK_TOKEN);
    expect(next.candidateFingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it("extracts and canonicalizes one complete PEM private-key block", () => {
    expect(extractPemPrivateKeyBlock(PEM_A.split("\n"), 1, 1)).toBe(PEM_A);
    expect(extractPemPrivateKeyBlock(PEM_A.split("\n"), 2, 2)).toBeUndefined();
    expect(
      extractPemPrivateKeyBlock(
        ["-----BEGIN RSA PRIVATE KEY-----", "QUJDREVGR0g="],
        1,
        1,
      ),
    ).toBeUndefined();
  });

  it("gives all scanners the same fingerprint for one complete PEM block", () => {
    const rootDir = tempDir("clearance-ev-pem-");
    writeTree(rootDir, { "key.pem": `${PEM_A}\n` });
    const [root] = resolveRoots([rootDir]);
    const runKey = newRunKey();
    const next = (["native", "gitleaks", "trufflehog"] as const).map((scanner) =>
      extractEvidence(
        privateKeyOccurrence(scanner, root!.rootId, "key.pem"),
        root!,
        defaultConfig(),
        runKey,
      ),
    );

    expect(next.map((occ) => occ.extraction)).toEqual(["exact", "exact", "exact"]);
    expect(next.map((occ) => occ.candidate)).toEqual([PEM_A, PEM_A, PEM_A]);
    expect(new Set(next.map((occ) => occ.candidateFingerprint)).size).toBe(1);
    const clusters = clusterOccurrences(next, [
      { name: "native", enabled: true, status: "completed" },
      { name: "gitleaks", enabled: true, status: "completed" },
      { name: "trufflehog", enabled: true, status: "completed" },
    ]);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]?.foundBy).toEqual(["gitleaks", "native", "trufflehog"]);
  });

  it("does not fingerprint a PEM header without a complete block", () => {
    const rootDir = tempDir("clearance-ev-pem-partial-");
    writeTree(rootDir, { "key.pem": "-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGR0g=\n" });
    const [root] = resolveRoots([rootDir]);
    const next = extractEvidence(
      privateKeyOccurrence("native", root!.rootId, "key.pem"),
      root!,
      defaultConfig(),
      newRunKey(),
    );

    expect(next.extraction).toBe("inexact");
    expect(next.candidate).toBeUndefined();
    expect(next.candidateFingerprint).toBeUndefined();
  });

  it("fingerprints different complete PEM blocks differently", () => {
    const rootDir = tempDir("clearance-ev-pem-distinct-");
    writeTree(rootDir, { "a.pem": `${PEM_A}\n`, "b.pem": `${PEM_B}\n` });
    const [root] = resolveRoots([rootDir]);
    const runKey = newRunKey();
    const first = extractEvidence(
      privateKeyOccurrence("native", root!.rootId, "a.pem"),
      root!,
      defaultConfig(),
      runKey,
    );
    const second = extractEvidence(
      privateKeyOccurrence("native", root!.rootId, "b.pem"),
      root!,
      defaultConfig(),
      runKey,
    );

    expect(first.candidateFingerprint).toBeDefined();
    expect(second.candidateFingerprint).toBeDefined();
    expect(first.candidateFingerprint).not.toBe(second.candidateFingerprint);
  });
});
