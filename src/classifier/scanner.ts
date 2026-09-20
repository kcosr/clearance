import fs from "node:fs";
import { SourceMatcher } from "./matcher.js";
import type { ProgressSink } from "../progress.js";
import path from "node:path";
import { createHash } from "node:crypto";
import { candidateFingerprint, occurrenceId } from "../ids.js";
import type { ClassifiedFile } from "../walk.js";
import type { ClassifierCoverage, DetectorResult, Occurrence, RootRecord } from "../types.js";
import type { ClassifierConfig } from "./config.js";
import { invokeClassifier } from "./process.js";
import { CHILD_ERROR_CODES, response, type Finding } from "./protocol.js";

const digest = (b: Buffer) => `sha256:${createHash("sha256").update(b).digest("hex")}`;
const key = (file: ClassifiedFile) => `${file.rootId}\0${file.relPosix}`;
const inside = (p: string, root: string) => p === root || p.startsWith(root + path.sep);
export type Snapshot = { digest: string } | { error: string };

/** Open only an in-root regular file, with fixed allocation and lossless UTF-8. */
function readFile(file: ClassifiedFile, root: RootRecord, max: number): Buffer {
  const resolved = fs.realpathSync(file.absPath);
  if (!inside(resolved, root.realPath)) throw new Error("path-escape");
  const fd = fs.openSync(
    resolved,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
  );
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile()) throw new Error("not-regular");
    if (before.size > max) throw new Error("file-limit");
    if (fs.realpathSync(file.absPath) !== resolved) throw new Error("drift");
    const current = fs.statSync(resolved);
    if (current.dev !== before.dev || current.ino !== before.ino) throw new Error("drift");
    const bytes = Buffer.alloc(before.size + 1);
    let n = 0;
    while (n < bytes.length) {
      const read = fs.readSync(fd, bytes, n, bytes.length - n, null);
      if (!read) break;
      n += read;
    }
    const after = fs.fstatSync(fd);
    if (
      n !== before.size ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      throw new Error("drift");
    return bytes.subarray(0, n);
  } finally {
    fs.closeSync(fd);
  }
}

export function captureSnapshots(
  files: ClassifiedFile[],
  roots: RootRecord[],
  config: ClassifierConfig,
): Map<string, Snapshot> {
  const snapshots = new Map<string, Snapshot>();
  for (const file of files.filter((f) => f.kind === "scannable")) {
    try {
      const root = roots.find((r) => r.rootId === file.rootId)!;
      snapshots.set(key(file), { digest: digest(readFile(file, root, config.maxFileBytes)) });
    } catch {
      snapshots.set(key(file), { error: "snapshot-unavailable" });
    }
  }
  return snapshots;
}

class WorkBudget {
  constructor(private remaining: number) {}
  charge(bytes: number) {
    this.remaining -= bytes + 1;
    if (this.remaining < 0) throw new Error("resolution-limit");
  }
}

function mapFindings(
  findings: Finding[],
  text: string,
  file: ClassifiedFile,
  config: ClassifierConfig,
  runKey: Buffer,
  budget: WorkBudget,
): Occurrence[] {
  type Hit = { start: number; end: number; finding: Finding; severity: Occurrence["severity"] };
  const hits: Hit[] = [],
    searched = new Set<string>();
  const fingerprints = new Map<string, string>();
  const byText = new Map<string, Array<{ finding: Finding; severity: Occurrence["severity"] }>>();
  for (const finding of findings) {
    const category = config.policy.categories.find((c) => c.id === finding.category);
    if (!category || !category.reasons.includes(finding.reason))
      throw new Error("invalid-vocabulary");
    const identity = JSON.stringify(finding);
    if (searched.has(identity)) continue;
    searched.add(identity);
    const group = byText.get(finding.text) ?? [];
    group.push({ finding, severity: category.severity });
    byText.set(finding.text, group);
  }
  if (!byText.size) return [];
  const patterns = [...byText.keys()],
    found = new Set<number>();
  const matcher = new SourceMatcher(patterns, (bytes) => budget.charge(bytes));
  matcher.scan(text, (pattern, index) => {
    found.add(pattern);
    const value = patterns[pattern]!;
    const start = index,
      end = start + value.length;
    for (const entry of byText.get(value)!) {
      budget.charge(63);
      if (hits.length >= config.maxFindings) throw new Error("finding-limit");
      hits.push({ start, end, ...entry });
    }
  });
  if (found.size !== patterns.length) throw new Error("invalid-source");
  for (const value of patterns) fingerprints.set(value, candidateFingerprint(runKey, value));
  // Sparse endpoint index: one forward Unicode scan, O(findings) retained metadata.
  type Coordinate = { line: number; column: number; byte: number; lineStart: number };
  const points = [...new Set(hits.flatMap((h) => [h.start, h.end]))].sort((a, b) => a - b);
  const coordinates = new Map<number, Coordinate>();
  let position = 0,
    byte = 0,
    line = 1,
    column = 1,
    lineStart = 0;
  budget.charge(Buffer.byteLength(text));
  for (const point of points) {
    while (position < point) {
      const scalar = text.codePointAt(position)!;
      const width = scalar > 0xffff ? 2 : 1;
      byte += scalar < 0x80 ? 1 : scalar < 0x800 ? 2 : scalar < 0x10000 ? 3 : 4;
      position += width;
      if (scalar === 10) {
        line++;
        column = 1;
        lineStart = position;
      } else column += width;
    }
    if (position !== point) throw new Error("invalid-source");
    coordinates.set(point, { line, column, byte, lineStart });
  }
  return hits.map(({ start, end, finding, severity }) => {
    const a = coordinates.get(start)!,
      b = coordinates.get(end)!;
    const fields = {
      scanner: "classifier" as const,
      rootId: file.rootId,
      path: file.relPosix,
      lineStart: a.line,
      lineEnd: b.line,
      columnStart: a.column,
      columnEnd: b.column,
      ruleId: `classifier.${finding.category}.${finding.reason}`,
      source: { kind: "workingTree" as const },
    };
    // Bounded context extraction must not rescan a huge minified line for each hit.
    const excerpt = text.slice(a.lineStart, a.lineStart + 2048).split("\n", 1)[0]!;
    budget.charge(Buffer.byteLength(excerpt));
    return {
      ...fields,
      occurrenceId: occurrenceId(fields),
      category: finding.category,
      severity,
      byteStart: a.byte,
      byteEnd: b.byte,
      extraction: "exact" as const,
      candidate: finding.text,
      candidateFingerprint: fingerprints.get(finding.text)!,
      evidenceText: excerpt,
      matchLine: excerpt,
    };
  });
}

export async function scanClassifier(options: {
  progress?: ProgressSink;
  onFinding?: (occurrence: Occurrence) => void;
  config: ClassifierConfig;
  files: ClassifiedFile[];
  roots: RootRecord[];
  snapshots: Map<string, Snapshot>;
  runKey: Buffer;
  env: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  maxTotalFindings: number;
}): Promise<{
  detector: DetectorResult;
  occurrences: Occurrence[];
  coverage: ClassifierCoverage[];
}> {
  const { config } = options;
  const control = new AbortController();
  const abort = () => control.abort();
  const signal = control.signal;
  if (options.signal?.aborted) abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  // Install signal handlers only while this scanner owns child processes.
  if (!options.signal) {
    process.on("SIGINT", abort);
    process.on("SIGTERM", abort);
  }
  const coverage: ClassifierCoverage[] = options.files
    .filter((f) => f.kind !== "scannable")
    .map((f) => ({ rootId: f.rootId, path: f.relPosix, status: "excluded", reason: f.kind }));
  const files = options.files.filter((f) => f.kind === "scannable");
  const all: Occurrence[] = [];
  const env: NodeJS.ProcessEnv = {};
  let setupError: string | undefined;
  try {
    for (const [name, source] of Object.entries(config.env)) {
      if (options.env[source] === undefined) throw new Error("environment-unavailable");
      env[name] = options.env[source];
    }
  } catch {
    setupError = "environment-unavailable";
  }
  let next = 0;
  const worker = async () => {
    while (next < files.length) {
      const file = files[next++]!,
        root = options.roots.find((r) => r.rootId === file.rootId)!;
      const record: ClassifierCoverage = {
        rootId: file.rootId,
        path: file.relPosix,
        status: "failed",
      };
      coverage.push(record);
      const fileNumber = next;
      options.progress?.(`classifier file ${fileNumber}/${files.length}: preparing`);
      try {
        if (setupError) throw new Error(setupError);
        if (signal.aborted) throw new Error("cancelled");
        const snapshot = options.snapshots.get(key(file));
        if (!snapshot || "error" in snapshot) throw new Error("snapshot-unavailable");
        const bytes = readFile(file, root, config.maxFileBytes);
        if (digest(bytes) !== snapshot.digest) throw new Error("drift");
        let text: string;
        try {
          text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
        } catch {
          throw new Error("invalid-utf8");
        }
        if (text.includes("\0")) throw new Error("non-text");
        const budget = new WorkBudget(config.maxResolutionBytes);
        if (!text.length) {
          record.status = "empty";
          options.progress?.(`classifier file ${fileNumber}/${files.length}: ${record.status}`);
          continue;
        }
        const policy = {
          instructions: config.policy.instructions,
          categories: config.policy.categories.map(
            ({ severity: _severity, ...category }) => category,
          ),
        };
        const input = Buffer.from(
          JSON.stringify({
            version: 4,
            policy,
            target: { kind: "file", path: file.relPosix, text },
          }),
        );
        const output = await invokeClassifier(config, input, env, signal, (event) => {
          options.progress?.(
            `classifier file ${fileNumber}/${files.length}: ${event.stage === "planning" ? "planning chunks" : `chunks ${event.completed}/${event.total}`}`,
          );
        });
        const findings = response(output, config.maxFindings, config.maxFindingBytes);
        const mapped = mapFindings(findings, text, file, config, options.runKey, budget);
        if (signal.aborted) throw new Error("cancelled");
        if (digest(readFile(file, root, config.maxFileBytes)) !== snapshot.digest)
          throw new Error("drift");
        if (all.length + mapped.length > options.maxTotalFindings) throw new Error("finding-limit");
        all.push(...mapped);
        for (const occurrence of mapped) options.onFinding?.(occurrence);
        record.status = "completed";
        options.progress?.(`classifier file ${fileNumber}/${files.length}: completed`);
      } catch (error) {
        const known = new Set([
          "environment-unavailable",
          "snapshot-unavailable",
          "drift",
          "non-text",
          "invalid-utf8",
          ...CHILD_ERROR_CODES.map((code) => `child-${code}`),
          "file-limit",
          "resolution-limit",
          "finding-limit",
          "cancelled",
          "timeout",
          "input-limit",
          "output-limit",
          "stderr-limit",
          "launch-failed",
          "input-failed",
          "output-failed",
          "process-failed",
          "invalid-response",
          "invalid-finding",
          "invalid-vocabulary",
          "invalid-source",
        ]);
        options.progress?.(`classifier file ${fileNumber}/${files.length}: failed`);
        record.reason =
          error instanceof Error && known.has(error.message)
            ? error.message
            : "classification-failed";
      }
    }
  };
  try {
    await Promise.all(
      Array.from({ length: Math.min(config.concurrency, Math.max(1, files.length)) }, worker),
    );
  } finally {
    options.signal?.removeEventListener("abort", abort);
    if (!options.signal) {
      process.removeListener("SIGINT", abort);
      process.removeListener("SIGTERM", abort);
    }
  }
  const partial = coverage.some((c) => c.status === "failed");
  coverage.sort((a, b) => a.rootId.localeCompare(b.rootId) || a.path.localeCompare(b.path));
  return {
    detector: {
      name: "classifier",
      enabled: true,
      status: setupError ? "failed" : partial ? "partial" : "completed",
      ...(setupError
        ? { error: setupError }
        : partial
          ? { error: "classification-incomplete" }
          : {}),
    },
    occurrences: all,
    coverage,
  };
}

export function verifySnapshots(
  files: ClassifiedFile[],
  roots: RootRecord[],
  snapshots: Map<string, Snapshot>,
  config: ClassifierConfig,
  coverage: ClassifierCoverage[],
): void {
  for (const file of files.filter((f) => f.kind === "scannable")) {
    const snapshot = snapshots.get(key(file));
    if (!snapshot || "error" in snapshot) continue;
    try {
      const root = roots.find((r) => r.rootId === file.rootId)!;
      if (digest(readFile(file, root, config.maxFileBytes)) === snapshot.digest) continue;
    } catch {
      /* disappearing/replaced files are drift too */
    }
    const row = coverage.find((c) => c.rootId === file.rootId && c.path === file.relPosix);
    if (row) {
      row.status = "failed";
      row.reason = "drift";
    }
  }
}
