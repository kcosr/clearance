/** Strict executable protocol: duplicate keys and malformed Unicode are errors. */
export function strictJson(bytes: Buffer): unknown {
  try {
    return parseStrictJson(bytes);
  } catch {
    // Decoder/parser errors can include source snippets; expose fixed metadata.
    throw new Error("invalid-response");
  }
}

function parseStrictJson(bytes: Buffer): unknown {
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  let i = 0;
  const fail = (): never => {
    throw new Error("invalid-response");
  };
  const ws = () => {
    while (/[\x20\t\n\r]/.test(text[i] ?? "x")) i++;
  };
  const string = (): string => {
    const start = i++;
    while (i < text.length) {
      if (text[i] === "\\") {
        i += 2;
        continue;
      }
      if (text[i++] === '"') {
        const s: unknown = JSON.parse(text.slice(start, i));
        if (typeof s !== "string" || /[\uD800-\uDFFF]/u.test(s)) fail();
        return s as string;
      }
    }
    return fail();
  };
  const value = (depth: number): void => {
    if (depth > 32) fail();
    ws();
    const ch = text[i];
    if (ch === '"') {
      string();
      return;
    }
    if (ch === "{" || ch === "[") {
      const object = ch === "{";
      const close = object ? "}" : "]";
      const keys = new Set<string>();
      i++;
      ws();
      if (text[i] === close) {
        i++;
        return;
      }
      while (i < text.length) {
        ws();
        if (object) {
          if (text[i] !== '"') fail();
          const key = string();
          if (keys.has(key)) fail();
          keys.add(key);
          ws();
          if (text[i++] !== ":") fail();
        }
        value(depth + 1);
        ws();
        if (text[i] === close) {
          i++;
          return;
        }
        if (text[i++] !== ",") fail();
      }
      fail();
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
      text.slice(i),
    );
    if (!token) fail();
    i += token![0].length;
  };
  value(0);
  ws();
  if (i !== text.length) fail();
  return JSON.parse(text);
}

export type Finding = { text: string; category: string; reason: string };

export function response(bytes: Buffer, maxFindings: number, maxFindingBytes: number): Finding[] {
  const raw = strictJson(bytes);
  const object = (x: unknown): x is Record<string, unknown> =>
    !!x && typeof x === "object" && !Array.isArray(x);
  if (
    !object(raw) ||
    Object.keys(raw).sort().join() !== "findings,status,version" ||
    raw.version !== 2 ||
    raw.status !== "complete" ||
    !Array.isArray(raw.findings) ||
    raw.findings.length > maxFindings
  )
    throw new Error("invalid-response");
  return raw.findings.map((f: unknown) => {
    if (
      !object(f) ||
      Object.keys(f).sort().join() !== "category,reason,text" ||
      typeof f.text !== "string" ||
      !f.text.length ||
      Buffer.byteLength(f.text) > maxFindingBytes ||
      typeof f.category !== "string" ||
      typeof f.reason !== "string"
    )
      throw new Error("invalid-finding");
    return { text: f.text, category: f.category, reason: f.reason };
  });
}

/** Fixed executable failure vocabulary shared with the classifier contract. */
export const CHILD_ERROR_CODES = [
  "invalid_request",
  "configuration_error",
  "provider_unavailable",
  "provider_overloaded",
  "provider_refused",
  "provider_incomplete",
  "invalid_output",
  "invalid_output_schema",
  "invalid_output_source",
  "invalid_output_policy",
  "output_limit",
  "deadline",
  "cancelled",
  "process_failed",
  "admission_exhausted",
] as const;
export type ChildErrorCode = (typeof CHILD_ERROR_CODES)[number];

/** Only strict fixed error envelopes may enter metadata-only reporting. */
export function childErrorCode(bytes: Buffer): ChildErrorCode | undefined {
  try {
    const raw = strictJson(bytes);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
    const error = raw as Record<string, unknown>;
    if (
      Object.keys(error).sort().join() !== "code,status,version" ||
      error.version !== 2 ||
      error.status !== "error" ||
      typeof error.code !== "string" ||
      !CHILD_ERROR_CODES.includes(error.code as ChildErrorCode)
    )
      return undefined;
    return error.code as ChildErrorCode;
  } catch {
    return undefined;
  }
}
