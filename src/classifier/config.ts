import path from "node:path";
import { z } from "zod";
import { SEVERITIES } from "../types.js";

const text = (max: number) =>
  z
    .string()
    .min(1)
    .refine((s) => !/[\uD800-\uDFFF]/u.test(s) && !s.includes("\0") && Buffer.byteLength(s) <= max);
const identifier = z
  .string()
  .regex(/^[A-Za-z][A-Za-z0-9_.-]*$/)
  .max(64);
const unique = (values: string[]) => new Set(values).size === values.length;
const category = z
  .object({
    id: identifier.max(60),
    reasons: z.array(identifier).min(1).max(64).refine(unique),
    description: text(512)
      .refine((s) => !/\p{Cc}/u.test(s))
      .optional(),
    inclusion: z.array(text(4096)).max(64).default([]),
    exclusion: z.array(text(4096)).max(64).default([]),
    examples: z.array(text(4096)).max(64).default([]),
    severity: z.enum(SEVERITIES),
  })
  .strict();

export const ClassifierConfigSchema = z
  .object({
    enabled: z.boolean(),
    executable: z.string(),
    args: z.array(z.string().refine((s) => !s.includes("\0"))).max(128),
    // Values are environment-variable names, never credential values in reports.
    env: z.record(
      z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
      z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
    ),
    timeoutMs: z.number().int().min(1).max(1_800_000),
    concurrency: z.number().int().min(1).max(16),
    maxFileBytes: z
      .number()
      .int()
      .min(1)
      .max(64 * 1024 * 1024),
    maxInputBytes: z
      .number()
      .int()
      .min(1)
      .max(256 * 1024 * 1024),
    maxOutputBytes: z
      .number()
      .int()
      .min(1)
      .max(16 * 1024 * 1024),
    maxStderrBytes: z
      .number()
      .int()
      .min(1)
      .max(1024 * 1024),
    maxFindings: z.number().int().min(1).max(65536),
    maxFindingBytes: z
      .number()
      .int()
      .min(1)
      .max(1024 * 1024),
    maxResolutionBytes: z.number().int().min(1).max(1_073_741_824),
    policy: z
      .object({
        instructions: z
          .string()
          .refine(
            (s) =>
              !/[\uD800-\uDFFF]/u.test(s) && !s.includes("\0") && Buffer.byteLength(s) <= 32768,
          ),
        categories: z
          .array(category)
          .max(64)
          .refine((cs) => unique(cs.map((c) => c.id))),
      })
      .strict(),
  })
  .strict()
  .superRefine((c, ctx) => {
    if (!c.enabled) return;
    const required: Array<[string, boolean]> = [
      ["executable", path.isAbsolute(c.executable) && !c.executable.includes("\0")],
      ["policy", !!c.policy.instructions && !!c.policy.categories.length],
    ];
    for (const [field, valid] of required) {
      if (!valid)
        ctx.addIssue({ code: "custom", path: [field], message: "required for enabled classifier" });
    }
  });
export type ClassifierConfig = z.infer<typeof ClassifierConfigSchema>;
export const DEFAULT_CLASSIFIER: ClassifierConfig = {
  enabled: false,
  executable: "",
  args: [],
  env: {},
  timeoutMs: 300000,
  concurrency: 1,
  maxFileBytes: 8 * 1024 * 1024,
  maxInputBytes: 64 * 1024 * 1024,
  maxOutputBytes: 1024 * 1024,
  maxStderrBytes: 65536,
  maxFindings: 4096,
  maxFindingBytes: 65536,
  maxResolutionBytes: 256 * 1024 * 1024,
  policy: { instructions: "", categories: [] },
};
