import fs from "node:fs";
import type { AppConfig } from "../config.js";
import { DEFAULT_INSTRUCTIONS } from "./default-instructions.js";
import { HOST_CONTRACT } from "./schema.js";
import type { BatchRequest, BatchResponse } from "./schema.js";
import type { RootRecord } from "../types.js";

/**
 * Why the previous response for this batch was rejected. Present only on repair
 * attempts, which are triggered by schema/guardrail failures — never by
 * transport failures, which are retried by the model client instead.
 */
export type RepairContext = {
  /** 1-based repair attempt. */
  attempt: number;
  /** Host validation messages, e.g. unknown clusterId, bad enum. */
  diagnostics: string[];
  /** The rejected output, bounded. */
  rejected: string;
};

/** Per-batch context for the optional ranged read tool. */
export type BatchToolContext = {
  roots: RootRecord[];
  allowedPaths: Set<string>;
  budget: { remaining: number };
  onCall?: (event: { path: string; startLine: number; endLine: number; ok: boolean; truncated?: boolean; error?: string }) => void;
};

/**
 * The model conversation for one attempt. Captured only at traceDetail "full";
 * it contains the prompt, every tool exchange, and the raw provider responses,
 * so it can carry secrets.
 */
export type Transcript = {
  history?: unknown;
  rawResponses?: unknown;
  /** The system instructions passed to the agent. */
  instructions?: string;
  /** The tool definitions (name, description, parameter schema) passed to the agent. */
  tools?: Array<{ name: string; description: string; parameters: unknown }>;
};

export type ValidatorRuntime = {
  validateBatch(
    request: BatchRequest,
    instructions: string,
    repair?: RepairContext,
    tools?: BatchToolContext,
    /** Receives incremental trace context before and after the model call. */
    onTranscript?: (transcript: Transcript) => void,
  ): Promise<BatchResponse>;
};

export function loadInstructions(config: AppConfig): string {
  if (config.llm.instructions) {
    if (!fs.existsSync(config.llm.instructions)) {
      throw Object.assign(new Error(`llm instructions not found: ${config.llm.instructions}`), {
        code: "config-missing",
      });
    }
    return `${fs.readFileSync(config.llm.instructions, "utf8").trim()}\n\n${HOST_CONTRACT}`;
  }
  if (config.llm.instructionsText) {
    return `${config.llm.instructionsText.trim()}\n\n${HOST_CONTRACT}`;
  }
  return `${DEFAULT_INSTRUCTIONS.trim()}\n\n${HOST_CONTRACT}`;
}

export function createScriptedRuntime(
  handler: (request: BatchRequest) => BatchResponse | Promise<BatchResponse>,
): ValidatorRuntime {
  return {
    async validateBatch(request) {
      return handler(request);
    },
  };
}

export function createConstantRuntime(
  status: "confirmed" | "false_positive" | "uncertain" | "needs_context",
): ValidatorRuntime {
  return createScriptedRuntime((request) => ({
    batchId: request.batchId,
    verdicts: request.clusters.map((cluster) => ({
      clusterId: cluster.clusterId,
      status,
      confidence: status === "confirmed" || status === "false_positive" ? 0.9 : 0.4,
      rationale: `scripted ${status}`,
    })),
  }));
}
