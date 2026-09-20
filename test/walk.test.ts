import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { resolveRoots, walkRoots } from "../src/walk.js";
import { tempDir, writeTree } from "./helpers.js";

describe("walk", () => {
  it("classifies skip, archive, oversize, and scannable files", () => {
    const root = tempDir("clearance-walk-");
    writeTree(root, {
      "readme.md": "hi\n",
      "logo.png": Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      "secret.zip": "pk",
      "big.txt": "x".repeat(2_000_000),
      "node_modules/skip.js": "secret",
    });
    const config = defaultConfig();
    const walked = walkRoots(resolveRoots([root]), config);
    expect(walked.walk.scannable).toBe(1);
    expect(walked.walk.skippedHarmless).toBe(1);
    expect(walked.walk.archive).toBe(1);
    expect(walked.walk.oversize).toBe(1);
    expect(walked.coverage.some((item) => item.reason === "archive")).toBe(true);
    expect(walked.skipped.some((item) => item.reason === "harmless")).toBe(true);
  });

  it("treats NUL-prefixed files as harmless", () => {
    const root = tempDir("clearance-nul-");
    writeTree(root, { "blob.bin": Buffer.from([0, 1, 2, 3, 4]) });
    const walked = walkRoots(resolveRoots([root]), defaultConfig());
    expect(walked.walk.skippedHarmless).toBe(1);
    expect(walked.walk.scannable).toBe(0);
  });

  it("does not follow symlink escapes", () => {
    const root = tempDir("clearance-link-");
    writeTree(root, { "inside.txt": "ok" });
    fs.symlinkSync("/etc/passwd", path.join(root, "escape"));
    const walked = walkRoots(resolveRoots([root]), defaultConfig());
    expect(walked.skipped.some((item) => item.reason === "symlink-escape")).toBe(true);
  });

  it("rejects overlapping roots", () => {
    const root = tempDir("clearance-overlap-");
    fs.mkdirSync(path.join(root, "child"));
    expect(() => resolveRoots([root, path.join(root, "child")])).toThrow(/overlapping/);
  });

  it("honors include and exclude", () => {
    const root = tempDir("clearance-glob-");
    writeTree(root, { "keep.env": "a", "tmp/drop.env": "b" });
    const config = defaultConfig();
    config.scan.include = ["keep.env"];
    const walked = walkRoots(resolveRoots([root]), config);
    expect(walked.files.map((file) => file.relPosix)).toEqual(["keep.env"]);
  });
});
