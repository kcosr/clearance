import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { parseGitleaksReport } from "../src/scanners/gitleaks.js";
import { parseTrufflehogNdjson } from "../src/scanners/trufflehog.js";
import type { RootRecord } from "../src/types.js";

const root: RootRecord = {
  rootId: "root-1",
  supplied: "/tmp/app",
  realPath: "/tmp/app",
  git: { kind: "worktree", topLevel: "/tmp/app" },
};

describe("adapters", () => {
  it("parses redacted gitleaks working-tree findings", () => {
    const raw = fs.readFileSync(
      path.join(import.meta.dirname, "fixtures/scanners/gitleaks.json"),
      "utf8",
    );
    const occ = parseGitleaksReport(raw, {
      root,
      history: false,
      config: defaultConfig(),
      extraExclude: [],
    });
    expect(occ).toHaveLength(1);
    expect(occ[0]?.scanner).toBe("gitleaks");
    expect(occ[0]?.path).toBe("app.env");
    expect(occ[0]?.source).toEqual({ kind: "workingTree" });
    expect(occ[0]?.columnStart).toBe(17);
  });

  it("maps gitleaks history commits", () => {
    const raw = fs.readFileSync(
      path.join(import.meta.dirname, "fixtures/scanners/gitleaks-git.json"),
      "utf8",
    );
    const occ = parseGitleaksReport(raw, {
      root,
      history: true,
      config: defaultConfig(),
      extraExclude: [],
    });
    expect(occ[0]?.source).toEqual({ kind: "git", commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
  });

  it("rejects unredacted gitleaks secrets", () => {
    expect(() =>
      parseGitleaksReport(
        JSON.stringify([
          { RuleID: "slack", File: "app.env", StartLine: 1, Secret: "xoxb-not-redacted", Commit: "" },
        ]),
        { root, history: false, config: defaultConfig(), extraExclude: [] },
      ),
    ).toThrow(/unredacted/);
  });

  it("parses trufflehog filesystem ndjson without copying raw secrets", () => {
    const raw = fs.readFileSync(
      path.join(import.meta.dirname, "fixtures/scanners/trufflehog.ndjson"),
      "utf8",
    );
    const occ = parseTrufflehogNdjson(raw, {
      root,
      history: false,
      config: defaultConfig(),
      extraExclude: [],
    });
    expect(occ[0]?.scanner).toBe("trufflehog");
    expect(occ[0]?.path).toBe("app.env");
    expect(JSON.stringify(occ[0])).not.toContain("Raw");
  });

  it("parses trufflehog git metadata", () => {
    const raw = fs.readFileSync(
      path.join(import.meta.dirname, "fixtures/scanners/trufflehog-git.ndjson"),
      "utf8",
    );
    const occ = parseTrufflehogNdjson(raw, {
      root,
      history: true,
      config: defaultConfig(),
      extraExclude: [],
    });
    expect(occ[0]?.source.kind).toBe("git");
  });

  it("post-filters scanner paths with include/exclude", () => {
    const config = defaultConfig();
    config.scan.include = ["keep.env"];
    const occ = parseGitleaksReport(
      JSON.stringify([
        { RuleID: "slack", File: "keep.env", StartLine: 1, Secret: "REDACTED", Commit: "" },
        { RuleID: "slack", File: "drop.env", StartLine: 1, Secret: "REDACTED", Commit: "" },
      ]),
      { root, history: false, config, extraExclude: [] },
    );
    expect(occ.map((item) => item.path)).toEqual(["keep.env"]);
  });
});
