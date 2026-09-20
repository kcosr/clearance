import picomatch from "picomatch";
import path from "node:path";

export function toPosix(rel: string): string {
  return rel.split(path.sep).join("/");
}

export function matchesGlob(relPosix: string, pattern: string): boolean {
  const normalized = pattern.replace(/^\.\//, "");
  return picomatch(normalized, { dot: true, posix: true, bash: true })(relPosix);
}

/**
 * Excludes alone. Directories are pruned on excludes only: an include glob
 * describes files, so matching it against a directory name would prune the
 * subtree before any of its files were considered.
 */
export function excludedByGlobs(relPosix: string, exclude: string[]): boolean {
  return exclude.some((pattern) => matchesGlob(relPosix, pattern));
}

export function allowedByIncludeExclude(
  relPosix: string,
  include: string[],
  exclude: string[],
): boolean {
  if (exclude.some((pattern) => matchesGlob(relPosix, pattern))) return false;
  if (include.length === 0) return true;
  return include.some((pattern) => matchesGlob(relPosix, pattern));
}

export function filenameGlobMatch(relPosix: string, pattern: string): boolean {
  const base = relPosix.includes("/") ? relPosix.slice(relPosix.lastIndexOf("/") + 1) : relPosix;
  return matchesGlob(relPosix, pattern) || matchesGlob(base, pattern);
}
