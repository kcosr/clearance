import type { AppConfig } from "./config.js";
import type { Cluster, Occurrence } from "./types.js";

const DIRECTORY = "(?:test|tests|__tests__|fixtures|__fixtures__)";
// Test/spec markers describe source tests only: configuration such as
// application-test.properties or an OpenAPI spec is still deployable input.
const SOURCE_EXTENSIONS =
  "js|jsx|ts|tsx|mjs|cjs|mts|cts|py|go|rs|java|kt|kts|scala|rb|php|swift|c|cc|cpp|cxx|h|hpp|cs|fs|fsx|ex|exs|erl|clj|cljs|cljc|dart|lua|pl|r|jl|sh";
const SOURCE_TEST = `(?:[^/]+[._-](?:test|spec)(?:[._-][^/]*)?|(?:test|spec)[_-][^/]+)\\.(?:${SOURCE_EXTENSIONS})`;
// An explicit fixture marker can identify data files, regardless of extension.
const FIXTURE = "(?:[^/]+[._-]fixture(?:[._-][^/]*)?|fixture[_-][^/]+)";
const TEST_FIXTURE_PATTERN = `(?:^|/)${DIRECTORY}(?:/|$)|(?:^|/)(?:${SOURCE_TEST}|${FIXTURE})$`;
const fixturePath = new RegExp(TEST_FIXTURE_PATTERN, "i");

export function isTestFixturePath(relativePath: string): boolean {
  return fixturePath.test(relativePath);
}

/** Path hints are not model verdicts. Run after validation so the policy never
 * removes evidence or bypasses either screening pass. */
export function applyTestFixturePolicy(
  occurrences: Occurrence[],
  clusters: Cluster[],
  config: AppConfig,
): { occurrences: Occurrence[]; clusters: Cluster[] } {
  const nextOccurrences = occurrences.map(
    (occ): Occurrence =>
      isTestFixturePath(occ.path)
        ? {
            ...occ,
            pathContext: "test-fixture",
            ...(config.scan.excludeTestFixtures
              ? { policyExclusion: "test-fixture" as const }
              : {}),
          }
        : occ,
  );
  const byId = new Map(nextOccurrences.map((occ) => [occ.occurrenceId, occ]));
  const nextClusters = clusters.map((cluster): Cluster => {
    const members = cluster.occurrenceIds
      .map((id) => byId.get(id))
      .filter((occ): occ is Occurrence => occ !== undefined);
    const fixtures = members.filter((occ) => occ.pathContext === "test-fixture");
    if (!fixtures.length) return cluster;
    const allFixtures = members.length === fixtures.length;
    const annotated: Cluster = {
      ...cluster,
      pathContext: allFixtures ? "test-fixture" : "mixed",
      testFixtureOccurrenceIds: fixtures.map((occ) => occ.occurrenceId),
    };
    if (!config.scan.excludeTestFixtures) return annotated;
    annotated.policyExcludedOccurrenceIds = fixtures.map((occ) => occ.occurrenceId);
    if (allFixtures) {
      annotated.policyExclusion = "test-fixture";
      if (cluster.effectiveStatus === "open") annotated.effectiveStatus = "policy_excluded";
    }
    return annotated;
  });
  return { occurrences: nextOccurrences, clusters: nextClusters };
}
