import fs from "node:fs";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import { z } from "zod";
import { readPackagedPolicy } from "../packaged-policy.js";
import { SEVERITIES } from "../types.js";

const NativeRuleSchema = z.object({
  id: z.string().min(1),
  type: z.enum(["glob", "regex"]),
  pattern: z.string().min(1),
  pathGlob: z.string().optional(),
  severity: z.enum(SEVERITIES),
  category: z.string().min(1),
  message: z.string().optional(),
});

export type NativeRule = z.infer<typeof NativeRuleSchema>;

const RuleFileSchema = z.object({
  schema_version: z.string().optional(),
  rules: z.array(NativeRuleSchema).default([]),
});

function parseRuleFiles(files: Array<{ name: string; raw: string }>): NativeRule[] {
  const rules: NativeRule[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    const parsed = parseToml(file.raw);
    const fileRules = RuleFileSchema.parse(parsed).rules;
    for (const rule of fileRules) {
      if (seen.has(rule.id)) {
        throw Object.assign(new Error(`duplicate native rule id: ${rule.id}`), {
          code: "config-invalid",
        });
      }
      if (rule.type === "regex") {
        try {
          new RegExp(rule.pattern, "g");
        } catch (error) {
          throw Object.assign(new Error(`invalid native regex ${rule.id}`), {
            code: "config-invalid",
            cause: error,
          });
        }
      }
      seen.add(rule.id);
      rules.push(rule);
    }
  }
  return rules;
}

export function loadNativeRules(rulesD: string): NativeRule[] {
  const packaged = readPackagedPolicy(rulesD);
  if (packaged !== undefined) {
    return parseRuleFiles([{ name: "default.toml", raw: packaged }]);
  }
  if (!rulesD || !fs.existsSync(rulesD)) {
    throw Object.assign(new Error(`rulesD not found: ${rulesD || "<empty>"}`), {
      code: "config-missing",
    });
  }
  const stat = fs.statSync(rulesD);
  if (!stat.isDirectory()) {
    throw Object.assign(new Error(`rulesD is not a directory: ${rulesD}`), {
      code: "config-invalid",
    });
  }
  const files = fs
    .readdirSync(rulesD)
    .filter((name) => name.endsWith(".toml"))
    .sort()
    .map((name) => ({ name, raw: fs.readFileSync(path.join(rulesD, name), "utf8") }));
  return parseRuleFiles(files);
}
