#!/usr/bin/env node
import { runClearance } from "./scan.js";

const result = await runClearance({ argv: process.argv.slice(2) });
process.exitCode = result.exitCode;

// Bun can keep its pooled fetch socket referenced after the model request has
// completed, including in compiled executables. All Clearance work and report
// writes have been awaited at this point. Flush terminal streams before the
// explicit exit so piped output is not truncated at the OS pipe-buffer size.
if ("Bun" in globalThis) {
  await Promise.all([
    new Promise<void>((resolve) => process.stdout.end(() => resolve())),
    new Promise<void>((resolve) => process.stderr.end(() => resolve())),
  ]);
  process.exit(result.exitCode);
}
