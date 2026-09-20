import type { Severity } from "../types.js";

export function classifyGitleaksRule(ruleId: string): { category: string; severity: Severity } {
  const id = ruleId.toLowerCase();
  if (id.includes("private") || id.includes("pkcs") || id.includes("pem")) {
    return { category: "private-key", severity: "critical" };
  }
  if (id.includes("slack")) return { category: "slack-token", severity: "high" };
  if (id.includes("stripe")) return { category: "stripe-key", severity: "high" };
  if (id.includes("aws")) return { category: "aws-key", severity: "high" };
  if (id.includes("github") || id.includes("gitlab")) return { category: "scm-token", severity: "high" };
  if (id.includes("password") || id.includes("secret") || id.includes("token") || id.includes("key")) {
    return { category: "secret", severity: "high" };
  }
  return { category: "secret", severity: "high" };
}

export function classifyTrufflehogDetector(name: string): { category: string; severity: Severity } {
  const id = name.toLowerCase();
  if (id.includes("private") || id.includes("pkcs") || id.includes("pem")) {
    return { category: "private-key", severity: "critical" };
  }
  if (id.includes("slack")) return { category: "slack-token", severity: "high" };
  if (id.includes("stripe")) return { category: "stripe-key", severity: "high" };
  if (id.includes("aws")) return { category: "aws-key", severity: "high" };
  if (id.includes("github") || id.includes("gitlab")) return { category: "scm-token", severity: "high" };
  return { category: "secret", severity: "high" };
}

export function isRedactedSecret(secret: string | undefined): boolean {
  if (!secret) return true;
  if (/^REDACTED/i.test(secret)) return true;
  if (secret.includes("*") && !/xox[baprs]-|sk_live_|AKIA[0-9A-Z]{16}/.test(secret)) return true;
  return false;
}
