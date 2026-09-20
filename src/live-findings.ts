import type { BatchCluster } from "./llm/schema.js";
import type { ClusterVerdict, Occurrence } from "./types.js";

/** Reversible quoting: preserve raw values without terminal controls or forged lines. */
export function terminalQuote(value: string): string {
  return JSON.stringify(value).replace(
    /[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/g,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

export function findingMessage(occurrence: Occurrence): string {
  const location = `${terminalQuote(occurrence.rootId)} ${terminalQuote(occurrence.path)}:${occurrence.lineStart}`;
  const history =
    occurrence.source.kind === "git" ? ` git=${terminalQuote(occurrence.source.commit)}` : "";
  const value =
    occurrence.matchKind === "filename"
      ? "filename match"
      : occurrence.candidate !== undefined
        ? `value=${terminalQuote(occurrence.candidate)}`
        : occurrence.matchLine !== undefined
          ? `source line=${terminalQuote(occurrence.matchLine)} (exact candidate unavailable)`
          : "candidate unavailable";
  return `finding [unverified] ${location}${history} ${occurrence.scanner}/${terminalQuote(occurrence.ruleId)}: ${value}`;
}

export function verdictMessage(
  cluster: BatchCluster,
  verdict: ClusterVerdict,
  canOverride: boolean,
): string {
  const history = cluster.evidence.commit ? ` git=${terminalQuote(cluster.evidence.commit)}` : "";
  const value =
    cluster.evidence.candidate === undefined
      ? ""
      : ` value=${terminalQuote(cluster.evidence.candidate)}`;
  const rationale = verdict.rationale === undefined ? "" : `: ${terminalQuote(verdict.rationale)}`;
  return `LLM verdict [${canOverride ? "pending final policy" : "advisory"}] ${terminalQuote(cluster.rootId)} ${terminalQuote(cluster.path)}:${cluster.lineStart}${history}${value} ${verdict.status}${rationale}`;
}
