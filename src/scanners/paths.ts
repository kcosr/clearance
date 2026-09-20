import fs from "node:fs";
import path from "node:path";
import { allowedByIncludeExclude, toPosix } from "../globs.js";
import type { AppConfig } from "../config.js";
import type { RootRecord } from "../types.js";
import { scanRelativeFromRepo } from "../walk.js";

export function relativizeToRoot(file: string, root: string): string | undefined {
  const abs = path.isAbsolute(file) ? path.normalize(file) : path.resolve(root, file);
  const rel = path.relative(root, abs);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return undefined;
  return toPosix(rel);
}

export function postFilterPath(
  relPosix: string,
  config: AppConfig,
  extraExclude: string[],
): boolean {
  return allowedByIncludeExclude(relPosix, config.scan.include, [
    ...config.scan.exclude,
    ...extraExclude,
  ]);
}

export function historyPathForRoot(root: RootRecord, scannerPath: string): string | undefined {
  const invokeRoot = root.git.topLevel ?? root.realPath;
  const repoRel = relativizeToRoot(scannerPath, invokeRoot);
  if (repoRel === undefined) return undefined;
  return scanRelativeFromRepo(root, repoRel);
}

export function fileExists(filePath: string): boolean {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

export function megabytesFromMaxBytes(maxFileBytes: number): number | undefined {
  if (maxFileBytes <= 0) return undefined;
  return Math.max(1, Math.ceil(maxFileBytes / (1024 * 1024)));
}
