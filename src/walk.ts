import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { allowedByIncludeExclude, excludedByGlobs, toPosix } from "./globs.js";
import type { AppConfig } from "./config.js";
import type { CoverageFinding, RootRecord, SkippedFile, WalkSummary } from "./types.js";

export type ClassifiedFile = {
  rootId: string;
  relPosix: string;
  absPath: string;
  kind: "scannable" | "harmless" | "archive" | "oversize" | "unreadable";
  size: number;
  mtimeMs: number;
};

export type WalkResult = {
  files: ClassifiedFile[];
  skipped: SkippedFile[];
  coverage: CoverageFinding[];
  walk: WalkSummary;
};

function extOf(relPosix: string): string {
  const base = relPosix.includes("/") ? relPosix.slice(relPosix.lastIndexOf("/") + 1) : relPosix;
  const dot = base.lastIndexOf(".");
  return dot >= 0 ? base.slice(dot).toLowerCase() : "";
}

export function detectGit(root: string): RootRecord["git"] {
  try {
    const bare = execFileSync("git", ["-C", root, "rev-parse", "--is-bare-repository"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (bare === "true") {
      return { kind: "bare", topLevel: path.resolve(root) };
    }
    const inside = execFileSync("git", ["-C", root, "rev-parse", "--is-inside-work-tree"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (inside === "true") {
      const top = execFileSync("git", ["-C", root, "rev-parse", "--show-toplevel"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim();
      return { kind: "worktree", topLevel: path.resolve(top) };
    }
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === "ENOENT") return { kind: "none", reason: "git-unavailable" };
    return { kind: "none", reason: "not-a-git-repository" };
  }
  return { kind: "none", reason: "not-a-git-repository" };
}

export function resolveRoots(supplied: string[]): RootRecord[] {
  const roots: RootRecord[] = [];
  for (const [index, raw] of supplied.entries()) {
    let realPath: string;
    try {
      const stat = fs.statSync(raw);
      if (!stat.isDirectory()) {
        throw Object.assign(new Error(`not a directory: ${raw}`), { code: "bad-root" });
      }
      realPath = fs.realpathSync(raw);
    } catch (error) {
      if ((error as { code?: string }).code === "bad-root") throw error;
      throw Object.assign(new Error(`root not found: ${raw}`), { code: "bad-root" });
    }
    roots.push({
      rootId: `root-${index + 1}`,
      supplied: raw,
      realPath,
      git: detectGit(realPath),
    });
  }
  for (let i = 0; i < roots.length; i += 1) {
    for (let j = i + 1; j < roots.length; j += 1) {
      const a = roots[i]!.realPath;
      const b = roots[j]!.realPath;
      if (a === b || a.startsWith(`${b}${path.sep}`) || b.startsWith(`${a}${path.sep}`)) {
        throw Object.assign(new Error("overlapping roots"), { code: "overlapping-roots" });
      }
    }
  }
  return roots;
}

function hasNulPrefix(absPath: string): boolean {
  const fd = fs.openSync(absPath, "r");
  try {
    const buf = Buffer.alloc(8192);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).includes(0);
  } finally {
    fs.closeSync(fd);
  }
}

function underDir(absPath: string, dir: string): boolean {
  return absPath === dir || absPath.startsWith(`${dir}${path.sep}`);
}

export function walkRoots(
  roots: RootRecord[],
  config: AppConfig,
  options: { extraExclude?: string[]; outputRealPath?: string } = {},
): WalkResult {
  const exclude = [...config.scan.exclude, ...(options.extraExclude ?? [])];
  const files: ClassifiedFile[] = [];
  const skipped: SkippedFile[] = [];
  const coverage: CoverageFinding[] = [];
  const walk: WalkSummary = {
    walked: 0,
    scannable: 0,
    skippedHarmless: 0,
    excludedByConfig: 0,
    archive: 0,
    oversize: 0,
    unreadable: 0,
  };

  const visit = (root: RootRecord, absDir: string, depth: number): void => {
    if (depth > config.scan.maxDepth) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const absPath = path.join(absDir, entry.name);
      if (options.outputRealPath && underDir(absPath, options.outputRealPath)) {
        walk.excludedByConfig += 1;
        continue;
      }
      const relPosix = toPosix(path.relative(root.realPath, absPath));
      if (!relPosix || relPosix === ".") continue;
      // Excludes prune directories. Includes are matched against files only —
      // testing an include glob against a directory name prunes the subtree
      // before its files are seen, so `--include '**/*.env'` would never descend
      // into `nested/`, and the walk would then disagree with the scanner
      // post-filter, which matches on file paths.
      if (excludedByGlobs(relPosix, exclude)) {
        walk.excludedByConfig += 1;
        continue;
      }
      if (
        !entry.isDirectory() &&
        !allowedByIncludeExclude(relPosix, config.scan.include, exclude)
      ) {
        walk.excludedByConfig += 1;
        continue;
      }
      if (entry.isSymbolicLink()) {
        let target: string;
        try {
          target = fs.realpathSync(absPath);
        } catch {
          skipped.push({ rootId: root.rootId, path: relPosix, reason: "symlink-escape" });
          continue;
        }
        if (!underDir(target, root.realPath)) {
          skipped.push({ rootId: root.rootId, path: relPosix, reason: "symlink-escape" });
          continue;
        }
      }
      let stat: fs.Stats;
      try {
        stat = entry.isSymbolicLink() ? fs.statSync(absPath) : fs.lstatSync(absPath);
      } catch {
        walk.unreadable += 1;
        skipped.push({ rootId: root.rootId, path: relPosix, reason: "unreadable" });
        if (config.scan.onUnreadable === "incomplete") {
          coverage.push({ rootId: root.rootId, path: relPosix, reason: "unreadable" });
        }
        continue;
      }
      if (stat.isDirectory()) {
        if (!entry.isSymbolicLink()) visit(root, absPath, depth + 1);
        continue;
      }
      if (!stat.isFile()) continue;
      walk.walked += 1;
      const ext = extOf(relPosix);
      if (config.scan.skipExtensions.includes(ext)) {
        walk.skippedHarmless += 1;
        skipped.push({ rootId: root.rootId, path: relPosix, reason: "harmless" });
        continue;
      }
      if (config.scan.archiveExtensions.includes(ext)) {
        walk.archive += 1;
        files.push({
          rootId: root.rootId,
          relPosix,
          absPath,
          kind: "archive",
          size: stat.size,
          mtimeMs: stat.mtimeMs,
        });
        skipped.push({ rootId: root.rootId, path: relPosix, reason: "archive" });
        if (config.scan.onArchive === "incomplete") {
          coverage.push({ rootId: root.rootId, path: relPosix, reason: "archive" });
        }
        continue;
      }
      if (config.scan.maxFileBytes > 0 && stat.size > config.scan.maxFileBytes) {
        walk.oversize += 1;
        files.push({
          rootId: root.rootId,
          relPosix,
          absPath,
          kind: "oversize",
          size: stat.size,
          mtimeMs: stat.mtimeMs,
        });
        skipped.push({ rootId: root.rootId, path: relPosix, reason: "oversize" });
        if (config.scan.onOversize === "incomplete") {
          coverage.push({ rootId: root.rootId, path: relPosix, reason: "oversize" });
        }
        continue;
      }
      try {
        if (hasNulPrefix(absPath)) {
          walk.skippedHarmless += 1;
          skipped.push({ rootId: root.rootId, path: relPosix, reason: "harmless" });
          continue;
        }
      } catch {
        walk.unreadable += 1;
        skipped.push({ rootId: root.rootId, path: relPosix, reason: "unreadable" });
        if (config.scan.onUnreadable === "incomplete") {
          coverage.push({ rootId: root.rootId, path: relPosix, reason: "unreadable" });
        }
        continue;
      }
      walk.scannable += 1;
      files.push({
        rootId: root.rootId,
        relPosix,
        absPath,
        kind: "scannable",
        size: stat.size,
        mtimeMs: stat.mtimeMs,
      });
    }
  };

  for (const root of roots) {
    if (root.git.kind === "bare") continue;
    visit(root, root.realPath, 1);
  }
  return { files, skipped, coverage, walk };
}

export function outputExcludeGlobs(outputDir: string, cwd: string): string[] {
  const resolved = path.resolve(cwd, outputDir);
  const rel = toPosix(path.relative(cwd, resolved));
  if (!rel || rel.startsWith("..")) return ["clearance-report/**"];
  return [`${rel}/**`, `${rel}`, "clearance-report/**"];
}

export function inventoryKey(file: ClassifiedFile): string {
  return `${file.rootId}\0${file.relPosix}\0${file.size}\0${file.mtimeMs}`;
}

export function detectDrift(before: ClassifiedFile[], after: ClassifiedFile[]): boolean {
  const scannable = (files: ClassifiedFile[]) =>
    files.filter((file) => file.kind === "scannable").map(inventoryKey).sort();
  const a = scannable(before);
  const b = scannable(after);
  if (a.length !== b.length) return true;
  return a.some((key, i) => key !== b[i]);
}

export function repoRelativePath(root: RootRecord, relPosix: string): string {
  if (!root.git.topLevel) return relPosix;
  const prefix = toPosix(path.relative(root.git.topLevel, root.realPath));
  if (!prefix || prefix === ".") return relPosix;
  return `${prefix}/${relPosix}`;
}

export function scanRelativeFromRepo(root: RootRecord, repoRelPosix: string): string | undefined {
  if (!root.git.topLevel) return repoRelPosix;
  const prefix = toPosix(path.relative(root.git.topLevel, root.realPath));
  if (!prefix || prefix === ".") return repoRelPosix;
  if (repoRelPosix === prefix) return ".";
  if (repoRelPosix.startsWith(`${prefix}/`)) return repoRelPosix.slice(prefix.length + 1);
  return undefined;
}
