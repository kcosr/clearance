import fs from "node:fs";
import path from "node:path";
import { renderTraceHtml } from "./trace-html.js";
import type { Transcript } from "./runtime.js";

/**
 * Debug trace for the LLM validate phase.
 *
 * There is no other way to see what the model actually returned: a response
 * that fails the guardrail is reduced to an `unreviewed` verdict with a 500
 * character rationale, and the raw output is discarded. This records each
 * attempt so a rejected batch can be diagnosed after the fact.
 *
 * `detail: "metadata"` records shapes and diagnostics only. `detail: "full"`
 * additionally records the system prompt, tools, message history, request, and
 * raw response. These can contain secrets because model requests carry matched
 * source content. Trace files are therefore created 0600 and re-chmodded on
 * every append, and should be treated as credential material.
 */
export type TraceDetail = "metadata" | "full";

export type TraceRecord = {
  ts: string;
  event: "batch-attempt" | "tool-call";
  batchId: string;
  attempt: number;
  repair: boolean;
  clusterIds: string[];
  durationMs: number;
  accepted: boolean;
  diagnostics?: string[];
  error?: string;
  /** Only when detail = "full". */
  request?: unknown;
  /** Only when detail = "full". */
  response?: unknown;
  /** Only when detail = "full": the model conversation for this attempt. */
  transcript?: Transcript;
  /** Present on tool-call records. */
  tool?: {
    name: string;
    path: string;
    startLine: number;
    endLine: number;
    ok: boolean;
    truncated?: boolean;
    error?: string;
  };
};

export type TraceSink = {
  append(record: TraceRecord): void;
};

export class NoopTraceSink implements TraceSink {
  append(): void {
    // discard
  }
}

export class JsonlTraceSink implements TraceSink {
  readonly #path: string;
  #initialized = false;

  constructor(filePath: string) {
    this.#path = path.resolve(filePath);
  }

  append(record: TraceRecord): void {
    if (!this.#initialized) {
      fs.mkdirSync(path.dirname(this.#path), { recursive: true });
      this.#initialized = true;
    }
    fs.appendFileSync(this.#path, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
    // appendFileSync only applies `mode` when it creates the file; re-assert so
    // a pre-existing world-readable file cannot silently collect secrets.
    fs.chmodSync(this.#path, 0o600);
  }
}

export function createTraceSink(traceFile: string): TraceSink {
  return traceFile ? new JsonlTraceSink(traceFile) : new NoopTraceSink();
}

/**
 * Writes the rendered view next to the JSONL, at the same 0600. Never throws:
 * a debug artifact must not be able to fail a scan.
 */
export function writeTraceHtml(
  traceFile: string,
  records: TraceRecord[],
  meta: { model: string; detail: string },
): string | undefined {
  if (!traceFile) return undefined;
  const dest = `${path.resolve(traceFile).replace(/\.jsonl$/, "")}.html`;
  try {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, renderTraceHtml(records, meta), { encoding: "utf8", mode: 0o600 });
    fs.chmodSync(dest, 0o600);
    return dest;
  } catch {
    return undefined;
  }
}
