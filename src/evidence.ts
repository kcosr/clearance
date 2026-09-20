import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import type { AppConfig } from "./config.js";
import { candidateFingerprint } from "./ids.js";
import type { ExtractionStatus, Occurrence, RootRecord } from "./types.js";
import { repoRelativePath } from "./walk.js";

/** Bounds a pathological minified line before it reaches a payload or report. */
const MATCH_LINE_MAX_CHARS = 2048;

const SECRET_SHAPES = [
  /xox[baprs]-[A-Za-z0-9-]+/g,
  /sk_live_[A-Za-z0-9]+/g,
  /sk_test_[A-Za-z0-9]+/g,
  /AKIA[0-9A-Z]{16}/g,
  /ghp_[A-Za-z0-9]{36}/g,
  /github_pat_[A-Za-z0-9_]+/g,
];

const PEM_PRIVATE_KEY_BEGIN = /^-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----$/;

export function sliceLineColumns(line: string, startCol: number, endCol: number): string {
  if (startCol <= 0 || endCol <= 0 || endCol < startCol) return "";
  const inclusive = line.slice(startCol - 1, endCol);
  const exclusive = endCol > startCol ? line.slice(startCol - 1, endCol - 1) : "";
  if (isSingleToken(inclusive)) return inclusive;
  if (isSingleToken(exclusive)) return exclusive;
  return inclusive.trim();
}

function isSingleToken(value: string): boolean {
  return value.length > 0 && !/\s/.test(value);
}

export function extractTokenFromLine(line: string): string | undefined {
  const hits: string[] = [];
  for (const shape of SECRET_SHAPES) {
    shape.lastIndex = 0;
    for (const match of line.matchAll(shape)) {
      if (match[0]) hits.push(match[0]);
    }
  }
  const unique = [...new Set(hits)];
  return unique.length === 1 ? unique[0] : undefined;
}

/**
 * Extract one complete PEM private-key block whose BEGIN marker is inside the
 * detector-reported range. A PEM header alone is not a secret identity: every
 * key of the same type shares it, so fingerprinting only that line would
 * correlate unrelated keys. Lines retain their original whitespace and CR;
 * joining with LF therefore preserves an exact substring of the source.
 */
export function extractPemPrivateKeyBlock(
  lines: string[],
  lineStart: number,
  lineEnd: number,
): string | undefined {
  const first = Math.max(0, lineStart - 1);
  const last = Math.min(lines.length - 1, Math.max(lineStart, lineEnd) - 1);
  const candidates = new Set<string>();

  for (let index = first; index <= last; index += 1) {
    const begin = lines[index] ?? "";
    const match = begin.trim().match(PEM_PRIVATE_KEY_BEGIN);
    if (!match) continue;

    const endMarker = `-----END ${match[1]}-----`;
    const block = [begin];
    let hasBody = false;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const original = lines[cursor] ?? "";
      const value = original.trim();
      if (PEM_PRIVATE_KEY_BEGIN.test(value)) break;
      block.push(original);
      if (value === endMarker) {
        if (hasBody) candidates.add(block.join("\n"));
        break;
      }
      if (value.length > 0) hasBody = true;
    }
  }

  return candidates.size === 1 ? [...candidates][0] : undefined;
}

function readWorkingTree(absPath: string, maxFileBytes: number): string | undefined {
  try {
    const stat = fs.lstatSync(absPath);
    if (stat.isSymbolicLink()) {
      const target = fs.realpathSync(absPath);
      const root = path.dirname(absPath);
      // caller checks root containment
      void root;
      void target;
    }
    if (maxFileBytes > 0 && stat.size > maxFileBytes) return undefined;
    return fs.readFileSync(absPath, "utf8");
  } catch {
    return undefined;
  }
}

function readGitBlob(
  root: RootRecord,
  commit: string,
  relPosix: string,
  maxFileBytes: number,
): string | undefined {
  const gitRoot = root.git.topLevel ?? root.realPath;
  const gitPath = repoRelativePath(root, relPosix);
  try {
    const buf = execFileSync("git", ["-C", gitRoot, "show", `${commit}:${gitPath}`], {
      maxBuffer: maxFileBytes > 0 ? maxFileBytes + 1 : 8_000_000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (maxFileBytes > 0 && buf.length > maxFileBytes) return undefined;
    return buf.toString("utf8");
  } catch {
    return undefined;
  }
}

function contained(absPath: string, root: string): boolean {
  const resolved = path.resolve(absPath);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`);
}

function linesOf(text: string): string[] {
  return text.split(/\n/);
}

function snippet(
  lines: string[],
  lineStart: number,
  lineEnd: number,
  contextLines: number,
): string {
  const start = Math.max(1, lineStart - contextLines);
  const end = Math.min(lines.length, lineEnd + contextLines);
  return lines.slice(start - 1, end).join("\n");
}

export function extractEvidence(
  occurrence: Occurrence,
  root: RootRecord,
  config: AppConfig,
  runKey: Buffer,
): Occurrence {
  const absPath = path.resolve(root.realPath, occurrence.path);
  if (!contained(absPath, root.realPath)) {
    return { ...occurrence, extraction: "unavailable" };
  }
  try {
    if (fs.lstatSync(absPath).isSymbolicLink()) {
      const target = fs.realpathSync(absPath);
      if (!contained(target, root.realPath)) {
        return { ...occurrence, extraction: "unavailable" };
      }
    }
  } catch {
    // history-only paths may not exist in the working tree
  }

  const maxBytes = config.scan.maxFileBytes;
  const text =
    occurrence.source.kind === "git"
      ? readGitBlob(root, occurrence.source.commit, occurrence.path, maxBytes)
      : fs.existsSync(absPath)
        ? readWorkingTree(absPath, maxBytes)
        : undefined;
  if (text === undefined) {
    return { ...occurrence, extraction: "unavailable" };
  }

  const allLines = linesOf(text);
  const line = allLines[occurrence.lineStart - 1] ?? "";
  const context = snippet(
    allLines,
    occurrence.lineStart,
    occurrence.lineEnd,
    config.llm.batch.contextLines,
  );

  let candidate = occurrence.candidate;
  let extraction: ExtractionStatus = occurrence.extraction;
  const pemCandidate =
    occurrence.category === "private-key"
      ? extractPemPrivateKeyBlock(allLines, occurrence.lineStart, occurrence.lineEnd)
      : undefined;
  const reportedLineHasPemHeader = PEM_PRIVATE_KEY_BEGIN.test(line.trim());

  if (pemCandidate) {
    candidate = pemCandidate
      .split("\n")
      .map((value) => value.trim())
      .join("\n");
    extraction = "exact";
  } else if (occurrence.category === "private-key" && reportedLineHasPemHeader) {
    // A partial PEM block cannot safely share an identity with another key.
    candidate = undefined;
    extraction = "inexact";
  } else if (occurrence.scanner === "native" && occurrence.candidate) {
    extraction = "exact";
    candidate = occurrence.candidate;
  } else if (
    occurrence.scanner === "gitleaks" &&
    occurrence.columnStart &&
    occurrence.columnEnd &&
    occurrence.columnStart > 0 &&
    occurrence.columnEnd > 0 &&
    occurrence.lineStart === occurrence.lineEnd
  ) {
    const sliced = sliceLineColumns(line, occurrence.columnStart, occurrence.columnEnd);
    if (isSingleToken(sliced)) {
      candidate = sliced;
      extraction = "exact";
    } else {
      extraction = "inexact";
    }
  } else if (occurrence.scanner === "trufflehog") {
    const token = extractTokenFromLine(line);
    if (token) {
      candidate = token;
      extraction = "exact";
    } else {
      extraction = "inexact";
    }
  } else {
    extraction = occurrence.candidate ? "exact" : "inexact";
  }

  const next: Occurrence = {
    ...occurrence,
    extraction,
    evidenceText: context,
    // Captured whether or not we could isolate a candidate: an unrecognised
    // token still has a line, and that line is what makes the finding judgeable.
    ...(line.trim() ? { matchLine: line.trim().slice(0, MATCH_LINE_MAX_CHARS) } : {}),
  };
  if (extraction === "exact" && candidate) {
    next.candidate = candidate;
    next.candidateFingerprint = candidateFingerprint(runKey, candidate);
  } else {
    delete next.candidate;
    delete next.candidateFingerprint;
  }
  return next;
}
