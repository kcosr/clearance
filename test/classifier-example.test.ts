import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse, stringify } from "smol-toml";
import { expect, it } from "vitest";
import type { ClassifierConfig } from "../src/classifier/config.js";
import { runClearance } from "../src/scan.js";

it("runs the documented processor without a model and resolves repeated markers", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "classifier-example-"));
  try {
    const root = path.join(directory, "input");
    fs.mkdirSync(root);
    const file = path.join(root, "note.txt");
    fs.writeFileSync(file, "EXAMPLE_PRIVATE_DEMO\nEXAMPLE_PRIVATE_DEMO\n");
    const config = parse(
      fs.readFileSync(new URL("../examples/classifier.toml", import.meta.url), "utf8"),
    );
    const detectors = config.detectors as { classifier: ClassifierConfig };
    detectors.classifier.executable = fs.realpathSync(process.execPath);
    detectors.classifier.args = [
      fileURLToPath(new URL("../examples/marker-classifier.mjs", import.meta.url)),
      "--progress",
    ];
    const configPath = path.join(directory, "config.toml");
    const scan = () =>
      runClearance({
        argv: [
          "--config",
          configPath,
          "--no-native",
          "--no-gitleaks",
          "--no-trufflehog",
          "--no-llm",
          "--no-report",
          "--json",
          "--quiet",
          root,
        ],
        env: {},
        stdout: { write() {} },
        stderr: { write() {} },
      });
    fs.writeFileSync(configPath, stringify(config));
    const flagged = await scan();
    expect(flagged.outcome).toBe("denied");
    expect(flagged.occurrences).toHaveLength(2);
    expect(flagged.occurrences.every((item) => item.scanner === "classifier")).toBe(true);
    expect(flagged.artifacts).toBeNull();
    detectors.classifier.policy.categories[0]!.description = "Literal demonstration markers.";
    fs.writeFileSync(configPath, stringify(config));
    const described = await scan();
    expect(described.outcome).toBe("denied");
    expect(described.occurrences).toHaveLength(2);
    fs.writeFileSync(file, "ordinary text\n");
    expect((await scan()).outcome).toBe("clean");
    detectors.classifier.policy.instructions = "An unsupported classification policy.";
    fs.writeFileSync(configPath, stringify(config));
    const failed = await scan();
    expect(failed.outcome).toBe("incomplete");
    expect(failed.classifier?.files[0]?.reason).toBe("child-configuration_error");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
