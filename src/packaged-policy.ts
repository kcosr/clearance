declare const CLEARANCE_NATIVE_RULES_TEXT: string | undefined;
declare const CLEARANCE_GITLEAKS_CONFIG_TEXT: string | undefined;
declare const CLEARANCE_GITLEAKS_IGNORE_TEXT: string | undefined;

const PREFIX = "clearance:packaged/";

const embeddedPolicies: Readonly<Record<string, string | undefined>> = {
  "rules.d":
    typeof CLEARANCE_NATIVE_RULES_TEXT === "string" ? CLEARANCE_NATIVE_RULES_TEXT : undefined,
  "gitleaks.toml":
    typeof CLEARANCE_GITLEAKS_CONFIG_TEXT === "string" ? CLEARANCE_GITLEAKS_CONFIG_TEXT : undefined,
  "gitleaks.ignore":
    typeof CLEARANCE_GITLEAKS_IGNORE_TEXT === "string" ? CLEARANCE_GITLEAKS_IGNORE_TEXT : undefined,
};

export function packagedPolicyPath(name: string): string | undefined {
  return embeddedPolicies[name] === undefined ? undefined : `${PREFIX}${name}`;
}

export function readPackagedPolicy(policyPath: string): string | undefined {
  if (!policyPath.startsWith(PREFIX)) return undefined;
  return embeddedPolicies[policyPath.slice(PREFIX.length)];
}

export function isPackagedPolicyPath(policyPath: string): boolean {
  return policyPath.startsWith(PREFIX);
}
