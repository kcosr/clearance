import {
  Agent,
  OpenAIProvider,
  Runner,
  tool,
  type ModelSettings,
} from "@openai/agents";
import { z } from "zod";
import { readRange } from "./read-tool.js";
import type { BatchToolContext, Transcript } from "./runtime.js";
import type { AppConfig } from "../config.js";
import { BatchResponseSchema, type BatchResponse } from "./schema.js";
import type { ValidatorRuntime } from "./runtime.js";

export function buildModelSettings(config: AppConfig): ModelSettings {
  const chat = config.model.api === "chat_completions";
  const reasoning =
    config.model.reasoning === "off" ? undefined : { effort: config.model.reasoning };
  return {
    store: false,
    timeoutMs: config.model.timeoutMs,
    retry: {
      maxRetries: config.model.maxRetries,
      backoff: {
        initialDelayMs: 100,
        maxDelayMs: 100,
        multiplier: 1,
        jitter: false,
      },
    },
    ...(chat || config.model.maxOutputTokens === 0
      ? {}
      : { maxTokens: config.model.maxOutputTokens }),
    ...(reasoning === undefined ? {} : { reasoning }),
    ...(chat
      ? {
          providerData: {
            ...(config.model.maxOutputTokens > 0
              ? { max_completion_tokens: config.model.maxOutputTokens }
              : {}),
            ...(config.model.chatTemplateThinking === undefined
              ? {}
              : { chat_template_kwargs: { enable_thinking: config.model.chatTemplateThinking } }),
          },
        }
      : {}),
  };
}

/**
 * The ranged read tool, when enabled. `maxLines` is stated in the description
 * so the model asks for a legal window rather than discovering the bound by
 * being truncated.
 */
function buildTools(config: AppConfig, context: BatchToolContext | undefined) {
  if (!config.llm.tools.read || !context || config.llm.tools.maxCalls === 0) return [];
  const { maxLines } = config.llm.tools;
  return [
    tool({
      name: "read_file",
      description:
        `Read a line range from a file that already has a finding in this batch. ` +
        `At most ${maxLines} lines per call; a wider range is truncated to that many. ` +
        `Use it when the supplied evidence is not enough to decide, for example to see ` +
        `a file header, imports, or the enclosing function.`,
      parameters: z.object({
        path: z.string().describe("Repository-relative path, exactly as given in the cluster."),
        startLine: z.number().int().min(1).describe("First line to read, 1-based."),
        endLine: z.number().int().min(1).describe(`Last line to read, inclusive. At most ${maxLines} lines are returned.`),
      }),
      async execute({ path: target, startLine, endLine }) {
        const result = readRange(
          { path: target, startLine, endLine },
          { roots: context.roots, config, allowedPaths: context.allowedPaths, budget: context.budget },
        );
        context.onCall?.({
          path: target,
          startLine,
          endLine,
          ok: result.ok,
          ...(result.ok ? { truncated: result.truncated } : { error: result.error }),
        });
        return result.ok ? result.text : `error: ${result.error}`;
      },
    }),
  ];
}

export function createAgentsRuntime(config: AppConfig): ValidatorRuntime {
  const configured = config.model.apiKeyEnv ? process.env[config.model.apiKeyEnv] : undefined;
  // Compatible hosts may need no auth; the SDK still requires a non-empty apiKey.
  const apiKey = configured && configured.length > 0 ? configured : "no-key";
  const provider = new OpenAIProvider({
    baseURL: config.model.baseURL,
    apiKey,
    useResponses: config.model.api === "responses",
  });
  const settings = buildModelSettings(config);
  return {
    async validateBatch(request, instructions, repair, toolContext, onTranscript) {
      const tools = buildTools(config, toolContext);
      // Keep trace metadata separate from executable tool handlers. The SDK's
      // parameters field is already the JSON Schema sent to the model.
      const toolDescriptions = tools.map((t) => ({
        name: t.name,
        description: t.description,
        parameters: t.parameters,
      }));
      const emitTranscript = (transcript: Transcript): void => {
        try {
          onTranscript?.(transcript);
        } catch {
          // tracing must never break a run
        }
      };
      const agent = new Agent({
        name: "Clearance validator",
        model: config.model.model,
        instructions,
        tools,
        outputType: BatchResponseSchema,
        modelSettings: settings,
      });
      // Clearance records its own local LLM trace. Disable the SDK's separate
      // OpenAI exporter so it neither exports findings nor keeps Bun alive.
      const runner = new Runner({ modelProvider: provider, tracingDisabled: true });
      // A repair attempt must show the model what was wrong; re-sending the
      // identical request just produces the identical rejected output.
      const input = repair
        ? [
            `Your previous response for this batch was rejected (repair attempt ${repair.attempt}).`,
            ``,
            `Rejected output:`,
            repair.rejected,
            ``,
            `Validation errors:`,
            ...repair.diagnostics.map((line) => `- ${line}`),
            ``,
            `Return a corrected response for the same batch. Emit exactly one verdict per clusterId listed below, and no others.`,
            ``,
            JSON.stringify(request),
          ].join("\n")
        : JSON.stringify(request);
      // Instructions and tool definitions are known before the provider call.
      // Capture them now so failed and timed-out attempts remain diagnosable.
      emitTranscript({ instructions, tools: toolDescriptions });
      const result = await runner.run(agent, input);
      // history carries the message sequence including tool calls and returns;
      // rawResponses carries whatever the provider returned, which is where
      // reasoning shows up when the endpoint emits it.
      emitTranscript({ history: result.history, rawResponses: result.rawResponses });
      return result.finalOutput as BatchResponse;
    },
  };
}
