import type { ProgressSink } from "../progress.js";
import { batchId } from "../ids.js";
import type { AppConfig } from "../config.js";
import type { Cluster, ClusterVerdict, LlmStatus, Occurrence, RootRecord } from "../types.js";
import type { BatchCluster, BatchRequest, BatchResponse } from "./schema.js";
import { validateBatchResponse } from "./schema.js";
import type { BatchToolContext, RepairContext, Transcript, ValidatorRuntime } from "./runtime.js";
import { createTraceSink, writeTraceHtml, type TraceRecord, type TraceSink } from "./trace.js";

/** Bounded so a runaway response cannot blow the repair prompt's budget. */
const REJECTED_MAX_CHARS = 2000;

function serializeRejected(raw: unknown): string {
  try {
    return JSON.stringify(raw).slice(0, REJECTED_MAX_CHARS);
  } catch {
    return String(raw).slice(0, REJECTED_MAX_CHARS);
  }
}

function estimatedTokens(payload: unknown): number {
  return Math.ceil(Buffer.byteLength(JSON.stringify(payload), "utf8") / 3);
}

function clusterEvidence(cluster: Cluster, occurrences: Occurrence[]): BatchCluster["evidence"] {
  const members = occurrences.filter((occ) => cluster.occurrenceIds.includes(occ.occurrenceId));
  const representative =
    members.find((occ) => occ.source.kind === "workingTree" && occ.evidenceText) ??
    members.find((occ) => occ.evidenceText) ??
    members[0];
  const evidence: BatchCluster["evidence"] = {};
  if (!representative) return evidence;
  evidence.path = representative.path;
  if (representative.source.kind === "git") evidence.commit = representative.source.commit;
  // Enabling the stage is the decision to send content. Withholding it produced
  // verdicts that only restated the detector's own claim, so there is no
  // half-setting: the model sees the line, its context, and the candidate.
  if (representative.matchLine) evidence.line = representative.matchLine;
  if (representative.evidenceText) evidence.text = representative.evidenceText;
  if (representative.candidate) evidence.candidate = representative.candidate;
  return evidence;
}

export function buildBatchCluster(
  cluster: Cluster,
  occurrences: Occurrence[],
  config: AppConfig,
): BatchCluster {
  const historyLocs = cluster.locations.filter((loc) => loc.commit);
  const payload: BatchCluster = {
    clusterId: cluster.clusterId,
    presence: cluster.presence,
    stillInWorkingTree: cluster.presence !== "historical",
    rootId: cluster.rootId,
    path: cluster.path,
    lineStart: cluster.lineStart,
    lineEnd: cluster.lineEnd,
    category: cluster.category,
    severity: cluster.severity,
    foundBy: cluster.foundBy,
    notFoundBy: cluster.notFoundBy,
    ...(cluster.description === undefined ? {} : { description: cluster.description }),
    locations: cluster.locations,
    evidence: clusterEvidence(cluster, occurrences),
  };
  if (historyLocs.length > 0) {
    payload.history = {
      commitCountObserved: new Set(historyLocs.map((loc) => loc.commit)).size,
      note: "introduction/copy events, not every commit the secret remained",
      removedFromWorkingTree: cluster.presence === "historical",
    };
  }
  return payload;
}

export function partitionBatches(clusters: BatchCluster[], config: AppConfig): BatchRequest[] {
  const sorted = [...clusters].sort(
    (a, b) =>
      a.rootId.localeCompare(b.rootId) ||
      a.path.localeCompare(b.path) ||
      a.lineStart - b.lineStart ||
      a.clusterId.localeCompare(b.clusterId),
  );
  const batches: BatchRequest[] = [];
  let current: BatchCluster[] = [];
  const fits = (next: BatchCluster[]): boolean => {
    if (next.length > config.llm.batch.maxClusters) return false;
    const payload = { batchId: "probe", clusters: next };
    if (Buffer.byteLength(JSON.stringify(payload), "utf8") > config.llm.batch.maxBytes)
      return false;
    if (estimatedTokens(payload) > config.llm.batch.maxTokens) return false;
    return true;
  };
  for (const cluster of sorted) {
    const candidate = [...current, cluster];
    if (current.length > 0 && !fits(candidate)) {
      batches.push({ batchId: batchId(batches.length + 1), clusters: current });
      current = [cluster];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) batches.push({ batchId: batchId(batches.length + 1), clusters: current });
  return batches;
}

function scrubRationale(rationale: string, occurrences: Occurrence[], cluster: Cluster): string {
  const candidates = occurrences
    .filter((occ) => cluster.occurrenceIds.includes(occ.occurrenceId) && occ.candidate)
    .map((occ) => occ.candidate!);
  let next = rationale;
  for (const candidate of candidates) {
    if (next.includes(candidate)) next = next.split(candidate).join("[redacted]");
    if (candidate.length >= 8) {
      for (let i = 0; i <= candidate.length - 8; i += 1) {
        const slice = candidate.slice(i, i + 8);
        if (next.includes(slice)) next = next.split(slice).join("[redacted]");
      }
    }
  }
  return next;
}

export function applyVerdicts(
  clusters: Cluster[],
  verdicts: Map<string, ClusterVerdict>,
  occurrences: Occurrence[],
  canOverride: boolean,
): Cluster[] {
  return clusters.map((cluster) => {
    const verdict = verdicts.get(cluster.clusterId);
    if (!verdict) return cluster;
    const scrubbed = {
      ...verdict,
      ...(verdict.rationale === undefined
        ? {}
        : { rationale: scrubRationale(verdict.rationale, occurrences, cluster) }),
    };
    if (!canOverride) {
      return { ...cluster, llm: { ...scrubbed, advisory: true } };
    }
    let effectiveStatus = cluster.effectiveStatus;
    let effectiveSeverity = cluster.effectiveSeverity;
    if (scrubbed.status === "false_positive") effectiveStatus = "suppressed";
    if (scrubbed.severityOverride && (scrubbed.status === "confirmed" || !cluster.llm)) {
      effectiveSeverity = scrubbed.severityOverride;
    }
    if (scrubbed.status === "confirmed" && scrubbed.severityOverride) {
      effectiveSeverity = scrubbed.severityOverride;
    }
    return {
      ...cluster,
      llm: scrubbed,
      effectiveStatus,
      effectiveSeverity,
    };
  });
}

export async function runValidation(options: {
  progress?: ProgressSink;
  onVerdict?: (cluster: BatchCluster, verdict: ClusterVerdict) => void;
  clusters: Cluster[];
  occurrences: Occurrence[];
  config: AppConfig;
  runtime: ValidatorRuntime;
  instructions: string;
  onWarning: (message: string) => void;
  /** Scan roots, required for the ranged read tool to resolve paths. */
  roots?: RootRecord[];
  /** Injectable for tests; otherwise derived from `[llm].traceFile`. */
  trace?: TraceSink;
}): Promise<{ clusters: Cluster[]; status: LlmStatus; failed: boolean }> {
  const open = options.clusters.filter(
    (cluster) =>
      cluster.effectiveStatus === "open" &&
      cluster.foundBy.some((scanner) => scanner !== "classifier"),
  );
  if (open.length === 0) {
    return { clusters: options.clusters, status: "complete", failed: false };
  }
  const known = new Set(options.clusters.map((cluster) => cluster.clusterId));
  const batches = partitionBatches(
    open.map((cluster) => buildBatchCluster(cluster, options.occurrences, options.config)),
    options.config,
  );
  const verdicts = new Map<string, ClusterVerdict>();
  // Buffered as well as appended so the run can render an HTML view of itself.
  const collected: TraceRecord[] = [];
  const base: TraceSink = options.trace ?? createTraceSink(options.config.llm.traceFile);
  const trace: TraceSink = {
    append: (record) => {
      collected.push(record);
      base.append(record);
    },
  };
  const traceFull = options.config.llm.traceDetail === "full";
  const deadline = Date.now() + options.config.llm.timeoutMs;
  let timedOut = false;
  let hadFailure = false;

  for (const [batchIndex, batch] of batches.entries()) {
    options.progress?.(`LLM validation batch ${batchIndex + 1}/${batches.length}: starting`);
    if (Date.now() > deadline) {
      timedOut = true;
      for (const cluster of batch.clusters) {
        verdicts.set(cluster.clusterId, { status: "unreviewed", rationale: "phase-timeout" });
        options.onVerdict?.(cluster, { status: "unreviewed", rationale: "phase timeout" });
      }
      continue;
    }
    const remaining = deadline - Date.now();
    // Reads are confined to files this batch already has findings in, and the
    // call budget is per batch so one ambiguous cluster cannot starve the rest.
    const toolContext: BatchToolContext | undefined =
      options.config.llm.tools.read && options.roots
        ? {
            roots: options.roots,
            allowedPaths: new Set(batch.clusters.map((item) => item.path)),
            budget: { remaining: options.config.llm.tools.maxCalls },
            onCall: (event) => {
              trace.append({
                ts: new Date().toISOString(),
                event: "tool-call",
                batchId: batch.batchId,
                attempt: 0,
                repair: false,
                clusterIds: batch.clusters.map((item) => item.clusterId),
                durationMs: 0,
                accepted: event.ok,
                tool: { name: "read_file", ...event },
              });
            },
          }
        : undefined;
    const maxRepairs = Math.min(options.config.llm.maxRepairs, 2);
    let lastError = "";
    let accepted: BatchResponse | undefined;
    let repair: RepairContext | undefined;
    for (let attempt = 0; attempt <= maxRepairs; attempt += 1) {
      if (Date.now() > deadline) {
        timedOut = true;
        break;
      }
      const startedAt = Date.now();
      let transcript: Transcript | undefined;
      const record = (
        accepted: boolean,
        extra: { diagnostics?: string[]; error?: string; response?: unknown },
      ): void => {
        trace.append({
          ts: new Date(startedAt).toISOString(),
          event: "batch-attempt",
          batchId: batch.batchId,
          attempt,
          repair: repair !== undefined,
          clusterIds: batch.clusters.map((item) => item.clusterId),
          durationMs: Date.now() - startedAt,
          accepted,
          ...(extra.diagnostics === undefined ? {} : { diagnostics: extra.diagnostics }),
          ...(extra.error === undefined ? {} : { error: extra.error }),
          ...(traceFull
            ? { request: batch, response: extra.response, ...(transcript ? { transcript } : {}) }
            : {}),
        });
      };
      try {
        const raw = await Promise.race([
          options.runtime.validateBatch(
            batch,
            options.instructions,
            repair,
            toolContext,
            traceFull
              ? (next) => {
                  transcript = { ...transcript, ...next };
                }
              : undefined,
          ),
          new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error("batch-timeout")), Math.max(1, remaining));
          }),
        ]);
        const checked = validateBatchResponse(raw, batch, known);
        if (checked.ok) {
          accepted = checked.value;
          record(true, { response: raw });
          break;
        }
        lastError = checked.diagnostics.join("; ");
        record(false, { diagnostics: checked.diagnostics, response: raw });
        // Schema/guardrail failure: the next attempt is a repair and must carry
        // the rejected output plus the reasons back to the model.
        repair = {
          attempt: attempt + 1,
          diagnostics: checked.diagnostics,
          rejected: serializeRejected(raw),
        };
      } catch (error) {
        lastError = error instanceof Error ? error.message : "llm-error";
        record(false, { error: lastError });
        if (lastError === "batch-timeout") {
          timedOut = true;
          break;
        }
        break;
      }
    }
    options.progress?.(
      `LLM validation batch ${batchIndex + 1}/${batches.length}: ${accepted ? "completed" : "failed"}`,
    );
    if (!accepted) {
      hadFailure = true;
      for (const cluster of batch.clusters) {
        verdicts.set(cluster.clusterId, {
          status: "unreviewed",
          rationale: lastError.slice(0, 500) || "unreviewed",
        });
        options.onVerdict?.(cluster, {
          status: "unreviewed",
          rationale: timedOut ? "batch timeout" : "validation failed",
        });
      }
      continue;
    }
    for (const verdict of accepted.verdicts) {
      const cluster = batch.clusters.find((item) => item.clusterId === verdict.clusterId)!;
      verdicts.set(verdict.clusterId, {
        status: verdict.status,
        confidence: verdict.confidence,
        ...(verdict.severityOverride === undefined
          ? {}
          : { severityOverride: verdict.severityOverride }),
        rationale: verdict.rationale,
        ...(verdict.duplicateOf === undefined ? {} : { duplicateOf: verdict.duplicateOf }),
      });
      options.onVerdict?.(cluster, verdicts.get(verdict.clusterId)!);
    }
  }

  // Every trace append happens inside the batch loop above, so the rendered
  // view is complete here regardless of which return follows.
  if (options.config.llm.traceFile) {
    writeTraceHtml(options.config.llm.traceFile, collected, {
      model: options.config.model.model,
      detail: options.config.llm.traceDetail,
    });
  }

  if (options.config.llm.failurePolicy === "fallback" && hadFailure && !timedOut) {
    options.progress?.("LLM validation: batch verdicts discarded by failure policy");
    return { clusters: options.clusters, status: "failed", failed: false };
  }
  if (options.config.llm.failurePolicy === "fail" && (hadFailure || timedOut)) {
    options.progress?.("LLM validation: batch verdicts discarded by failure policy");
    return { clusters: options.clusters, status: "failed", failed: true };
  }
  options.progress?.(
    options.config.llm.canOverride
      ? "LLM validation: batch verdicts applied; final report includes all policies"
      : "LLM validation: batch verdicts are advisory; findings unchanged",
  );
  const next = applyVerdicts(
    options.clusters,
    verdicts,
    options.occurrences,
    options.config.llm.canOverride,
  );
  const status: LlmStatus =
    timedOut && options.config.llm.partialOnTimeout
      ? "partial"
      : hadFailure
        ? "partial"
        : "complete";
  if (timedOut)
    options.onWarning("clearance: warning: llm phase timed out; remaining clusters unreviewed");
  return { clusters: next, status, failed: false };
}
