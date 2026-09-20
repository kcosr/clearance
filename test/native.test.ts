import { describe, expect, it } from "vitest";
import path from "node:path";
import { loadNativeRules } from "../src/native/rules.js";
import { runNativeRules } from "../src/native/scan.js";
import { shareFile } from "../src/config.js";
import { resolveRoots, walkRoots } from "../src/walk.js";
import { defaultConfig } from "../src/config.js";
import { PEM_HEADER, tempDir, writeTree } from "./helpers.js";

describe("native", () => {
  it("fails closed when the configured rules directory is missing", () => {
    const missing = path.join(tempDir("clearance-missing-rules-"), "rules.d");
    expect(() => loadNativeRules(missing)).toThrow(/rulesD not found/);
  });

  it("loads packaged rules", () => {
    const rules = loadNativeRules(shareFile("rules.d"));
    expect(rules.map((rule) => rule.id).sort()).toEqual(["no-windows-exe", "private-key"]);
  });

  it("matches filename globs on archives and regex on scannable files", () => {
    const root = tempDir("clearance-native-");
    writeTree(root, {
      "tool.exe": "",
      "id_rsa": `${PEM_HEADER}\nAAAA\n-----END RSA PRIVATE KEY-----\n`,
    });
    const walked = walkRoots(resolveRoots([root]), defaultConfig());
    const hits = runNativeRules(walked.files, loadNativeRules(shareFile("rules.d")));
    expect(hits.some((hit) => hit.ruleId === "no-windows-exe" && hit.path === "tool.exe")).toBe(true);
    expect(hits.some((hit) => hit.ruleId === "private-key" && hit.path === "id_rsa")).toBe(true);
    const pem = hits.find((hit) => hit.ruleId === "private-key");
    expect(pem?.extraction).toBe("exact");
    expect(pem?.candidate).toBe(PEM_HEADER);
  });

  it("respects regex pathGlob", () => {
    const root = tempDir("clearance-pathglob-");
    writeTree(root, {
      "keep.env": `${PEM_HEADER}\n`,
      "skip.txt": `${PEM_HEADER}\n`,
    });
    const walked = walkRoots(resolveRoots([root]), defaultConfig());
    const hits = runNativeRules(walked.files, [
      {
        id: "pem-env",
        type: "regex",
        pattern: "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        pathGlob: "**/*.env",
        severity: "critical",
        category: "private-key",
      },
    ]);
    expect(hits.map((hit) => hit.path)).toEqual(["keep.env"]);
  });
});
