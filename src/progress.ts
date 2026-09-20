export type ClassifierProgress = {
  version: 1;
  type: "progress";
  stage: "planning" | "classifying";
  completed: number;
  total: number;
};
export type ProgressSink = (message: string) => void;

/** Timestamped human output. Callers must escape source text; never pass child diagnostics. */
export function progressSink(
  enabled: boolean,
  stream: { write(chunk: string): void },
): ProgressSink {
  return (message) => {
    if (enabled) {
      try {
        const timestamp = new Date().toISOString().slice(0, 19).replace("T", " ");
        stream.write(`${timestamp} UTC ${message}\n`);
      } catch {
        /* reporting cannot alter screening */
      }
    }
  };
}

export function classifierProgress(line: string): ClassifierProgress | undefined {
  try {
    const x: unknown = JSON.parse(line);
    if (!x || typeof x !== "object" || Array.isArray(x)) return undefined;
    const p = x as Record<string, unknown>;
    if (
      Object.keys(p).sort().join() !== "completed,stage,total,type,version" ||
      p.version !== 1 ||
      p.type !== "progress" ||
      (p.stage !== "planning" && p.stage !== "classifying") ||
      !Number.isSafeInteger(p.completed) ||
      !Number.isSafeInteger(p.total) ||
      Number(p.completed) < 0 ||
      Number(p.total) < Number(p.completed) ||
      Number(p.total) > 16384
    )
      return undefined;
    return p as ClassifierProgress;
  } catch {
    return undefined;
  }
}
