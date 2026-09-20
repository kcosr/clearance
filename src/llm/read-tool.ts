import fs from "node:fs";
import path from "node:path";
import type { AppConfig } from "../config.js";
import type { RootRecord } from "../types.js";

/**
 * Host side of the optional ranged read tool.
 *
 * The model may ask for more context around a finding it is judging. Two
 * distinct failure modes, deliberately handled differently:
 *
 * - Asking for more lines than `maxLines` is a reasonable request against a
 *   bound it cannot see, so the range is clamped and the result says so. The
 *   model can then ask for the next window.
 * - Asking for a path it is not allowed to read is refused outright. That is
 *   not "too much", it is out of scope, and retrying must not make it work.
 *
 * Reads are confined to files that already carry a finding in the batch being
 * judged. Scanned content is untrusted and can contain text crafted to steer a
 * model; restricting reads to files a detector already fired on means a repo
 * cannot place arbitrary content in front of the model of its own accord.
 */
export type ReadRequest = {
  path: string;
  startLine: number;
  endLine: number;
};

export type ReadResult =
  | { ok: true; text: string; truncated: boolean; returnedLines: number }
  | { ok: false; error: string };

export type ReadToolContext = {
  roots: RootRecord[];
  config: AppConfig;
  /** Relative paths carrying a finding in the current batch. */
  allowedPaths: Set<string>;
  /** Remaining calls for this batch; decremented by the host. */
  budget: { remaining: number };
};

function resolveInsideRoot(
  relPosix: string,
  roots: RootRecord[],
): { absPath: string } | { error: string } {
  for (const root of roots) {
    const absPath = path.resolve(root.realPath, relPosix);
    if (absPath !== root.realPath && !absPath.startsWith(`${root.realPath}${path.sep}`)) {
      continue;
    }
    let real: string;
    try {
      real = fs.realpathSync(absPath);
    } catch {
      continue;
    }
    // The same containment check evidence extraction uses: a symlink must not
    // be able to walk the read out of the scan root.
    if (real !== root.realPath && !real.startsWith(`${root.realPath}${path.sep}`)) {
      return { error: "path escapes the scan root" };
    }
    return { absPath: real };
  }
  return { error: "path is not inside a scan root" };
}

export function readRange(request: ReadRequest, context: ReadToolContext): ReadResult {
  if (context.budget.remaining <= 0) {
    return { ok: false, error: "read budget exhausted for this batch" };
  }
  const relPosix = request.path.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!context.allowedPaths.has(relPosix)) {
    return {
      ok: false,
      error: `not readable: ${relPosix} does not carry a finding in this batch`,
    };
  }
  const resolved = resolveInsideRoot(relPosix, context.roots);
  if ("error" in resolved) return { ok: false, error: resolved.error };

  const maxFileBytes = context.config.scan.maxFileBytes;
  let contents: string;
  try {
    const stat = fs.lstatSync(resolved.absPath);
    if (!stat.isFile()) return { ok: false, error: "not a regular file" };
    if (maxFileBytes > 0 && stat.size > maxFileBytes) {
      return { ok: false, error: "file exceeds scan.maxFileBytes" };
    }
    contents = fs.readFileSync(resolved.absPath, "utf8");
  } catch {
    return { ok: false, error: "unreadable" };
  }

  const lines = contents.split(/\n/);
  const maxLines = context.config.llm.tools.maxLines;
  const start = Math.max(1, Math.floor(request.startLine));
  const requestedEnd = Math.max(start, Math.floor(request.endLine));
  const cappedEnd = Math.min(requestedEnd, start + maxLines - 1);
  const end = Math.min(cappedEnd, lines.length);
  if (start > lines.length) {
    return { ok: false, error: `startLine ${start} is past end of file (${lines.length} lines)` };
  }

  context.budget.remaining -= 1;
  const slice = lines.slice(start - 1, end);
  const numbered = slice.map((line, index) => `${start + index}: ${line}`).join("\n");
  const truncated = requestedEnd > cappedEnd;
  const header = truncated
    ? `${relPosix} lines ${start}-${end} (requested ${start}-${requestedEnd}, truncated at maxLines=${maxLines})`
    : `${relPosix} lines ${start}-${end}`;
  return { ok: true, text: `${header}\n${numbered}`, truncated, returnedLines: slice.length };
}
