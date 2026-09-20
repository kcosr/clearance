import { expect, it } from "vitest";
import { runOn, tempDir } from "../helpers.js";
import { makeCurrentSecret } from "../fixtures/scripts/make-trees.js";

const enabled = process.env.CLEARANCE_LIVE_LLM === "1";

it.skipIf(!enabled)("optional live LLM validate", async () => {
  const root = tempDir("clearance-live-");
  makeCurrentSecret(root);
  const model = process.env.CLEARANCE_LIVE_LLM_MODEL ?? "local-model";
  const { result } = await runOn(root, ["--llm", "--model", model], { env: process.env });
  expect(["denied", "clean", "findings", "error"]).toContain(result.outcome);
});
