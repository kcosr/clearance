import { escapeHtml } from "../report/html-escape.js";
import type { TraceRecord } from "./trace.js";

/**
 * Renders a debug trace as a standalone page: what was asked, what the model
 * reasoned, what it answered, and every tool call in between.
 *
 * This is a private debug artifact, not a report. At traceDetail "full" it
 * contains the request payload, the raw provider responses, and the model's
 * reasoning, any of which can carry secrets. It is written next to the JSONL at
 * 0600 and must not be placed in the report output directory.
 */

const STYLE = `
body { margin:0; padding:2rem 2.25rem 4rem; background:#fff; color:#111;
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif; }
main { max-width:1100px; }
h1 { font-size:1.5rem; margin:0 0 0.25rem; }
h2 { font-size:1.05rem; margin:2rem 0 0.5rem; }
.sub { color:#666; margin-bottom:1.5rem; }
.warn { border:1px solid #d8b9b5; background:#fdf3f2; border-radius:3px;
  padding:0.7rem 0.9rem; margin:1rem 0; }
.cards { display:flex; flex-wrap:wrap; gap:0.5rem; margin:0.75rem 0 1.5rem; }
.card { border:1px solid #ddd; border-radius:3px; padding:0.5rem 0.8rem; min-width:7rem; }
.card span { display:block; color:#666; font-size:0.8rem; }
.card b { font-size:1.1rem; font-weight:700; }
.row { border:1px solid #ddd; border-radius:3px; margin:0 0 0.75rem; padding:0.7rem 0.9rem; }
.row.fail { border-color:#d09b95; background:#fdf7f6; }
.row.tool { border-color:#c9d4de; background:#f7fafc; }
.head { display:flex; gap:0.6rem; align-items:baseline; flex-wrap:wrap; }
.who { font-weight:700; }
.meta { color:#666; font-size:0.85rem; }
.tag { border:1px solid #ccc; border-radius:2px; padding:0 0.35rem; font-size:0.75rem; color:#444; }
.group { margin-top:0.8rem; padding-top:0.25rem; }
.group-title { color:#444; font-size:0.78rem; font-weight:700; letter-spacing:0.04em;
  text-transform:uppercase; }
details { margin-top:0.5rem; }
summary { cursor:pointer; color:#2b5f8a; font-size:0.85rem; }
pre { background:#f6f7f8; border:1px solid #e4e7ea; border-radius:3px; padding:0.6rem;
  overflow-x:auto; font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  white-space:pre-wrap; word-break:break-word; margin:0.4rem 0 0; }
.think { background:#fbf9f4; border-color:#e7ddc7; }
.empty { color:#666; font-style:italic; }
`;

function pretty(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object") {
          const rec = part as Record<string, unknown>;
          if (typeof rec.text === "string") return rec.text;
          if (typeof rec.content === "string") return rec.content;
        }
        return "";
      })
      .filter(Boolean)
      .join("\n");
  }
  return "";
}

/** Pull reasoning, system, user and assistant messages out of a captured history array. */
function conversation(history: unknown): {
  reasoning: string;
  system: string;
  assistant: string;
  user: string;
} {
  const out = { reasoning: "", system: "", assistant: "", user: "" };
  if (!Array.isArray(history)) return out;
  for (const item of history) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const kind = String(rec.role ?? rec.type ?? "");
    // Some providers return reasoning in rawContent with content left empty.
    const text = textOf(rec.content) || textOf(rec.rawContent);
    if (kind === "reasoning") out.reasoning += text;
    else if (kind === "system") out.system += text;
    else if (kind === "assistant") out.assistant += text;
    else if (kind === "user") out.user += text;
  }
  return out;
}

function block(label: string, body: string, cls = ""): string {
  if (!body.trim()) return "";
  return `<details><summary>${escapeHtml(label)}</summary><pre class="${cls}">${escapeHtml(body)}</pre></details>`;
}

function group(label: string, blocks: string[]): string {
  const body = blocks.filter(Boolean).join("");
  if (!body) return "";
  return `<section class="group"><div class="group-title">${escapeHtml(label)}</div>${body}</section>`;
}

function attemptRow(record: TraceRecord): string {
  const convo = conversation(record.transcript?.history);
  const status = record.accepted ? "accepted" : "rejected";
  const tags = [
    `<span class="tag">${escapeHtml(record.batchId)}</span>`,
    `<span class="tag">attempt ${record.attempt}</span>`,
    record.repair ? `<span class="tag">repair</span>` : "",
    `<span class="tag">${record.durationMs} ms</span>`,
  ].join("");
  return `<article class="row ${record.accepted ? "" : "fail"}">
<div class="head"><span class="who">${escapeHtml(status)}</span>${tags}</div>
<div class="meta">${escapeHtml(record.ts)} · ${record.clusterIds.length} cluster(s): ${escapeHtml(record.clusterIds.join(", "))}</div>
${record.diagnostics?.length ? `<div class="meta">diagnostics: ${escapeHtml(record.diagnostics.join("; "))}</div>` : ""}
${record.error ? `<div class="meta">error: ${escapeHtml(record.error)}</div>` : ""}
${group("Model configuration", [
  record.transcript?.instructions ? block("System prompt", record.transcript.instructions) : "",
  record.transcript?.tools ? block("Available tools", pretty(record.transcript.tools)) : "",
  block("Additional system messages", convo.system),
])}
${group("Conversation", [
  block("User messages", convo.user || (record.request ? pretty(record.request) : "")),
  block("Model reasoning", convo.reasoning, "think"),
  block("Assistant messages", convo.assistant),
  record.transcript?.history
    ? block("Complete message history", pretty(record.transcript.history))
    : "",
])}
${group("Payloads and results", [
  record.request ? block("Request payload", pretty(record.request)) : "",
  record.response ? block("Parsed response", pretty(record.response)) : "",
  record.transcript?.rawResponses
    ? block("Raw provider responses", pretty(record.transcript.rawResponses))
    : "",
])}
</article>`;
}

function toolRow(record: TraceRecord): string {
  const t = record.tool;
  if (!t) return "";
  const range = `${t.startLine}-${t.endLine}`;
  const outcome = t.ok ? (t.truncated ? "read (truncated)" : "read") : "refused";
  return `<article class="row tool">
<div class="head"><span class="who">${escapeHtml(t.name)}</span>
<span class="tag">${escapeHtml(outcome)}</span>
<span class="tag">${escapeHtml(record.batchId)}</span></div>
<div class="meta">${escapeHtml(record.ts)} · <code>${escapeHtml(t.path)}</code> lines ${escapeHtml(range)}${t.error ? ` · ${escapeHtml(t.error)}` : ""}</div>
</article>`;
}

export function renderTraceHtml(
  records: TraceRecord[],
  meta: { model: string; detail: string },
): string {
  const attempts = records.filter((r) => r.event === "batch-attempt");
  const tools = records.filter((r) => r.event === "tool-call");
  const rejected = attempts.filter((r) => !r.accepted).length;
  const anyTranscript = attempts.some((r) => r.transcript);
  const cards: Array<[string, string | number]> = [
    ["Model", meta.model],
    ["Detail", meta.detail],
    ["Attempts", attempts.length],
    ["Rejected", rejected],
    ["Tool calls", tools.length],
    ["Refused reads", tools.filter((r) => r.tool && !r.tool.ok).length],
  ];
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Clearance LLM trace</title>
<style>${STYLE}</style>
</head>
<body>
<main>
<h1>Clearance LLM trace</h1>
<p class="sub">Debug view of the validate phase: what was asked, what the model reasoned, and every tool call.</p>
<div class="warn"><strong>Private debug artifact.</strong> At <code>traceDetail = "full"</code> this page contains the request payload, the model's reasoning, and raw provider responses, any of which can carry secrets. Do not publish it alongside the reports.</div>
<div class="cards">${cards
    .map(
      ([label, value]) =>
        `<div class="card"><span>${escapeHtml(label)}</span><b>${escapeHtml(String(value))}</b></div>`,
    )
    .join("")}</div>
${
  anyTranscript
    ? ""
    : `<p class="empty">No conversation captured — run with <code>traceDetail = "full"</code> to record prompts, reasoning, and responses.</p>`
}
<h2>Timeline</h2>
${
  records.length === 0
    ? `<p class="empty">No trace records.</p>`
    : records.map((r) => (r.event === "tool-call" ? toolRow(r) : attemptRow(r))).join("\n")
}
</main>
</body>
</html>
`;
}
