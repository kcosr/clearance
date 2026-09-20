# Development and local testing

[Overview](../README.md) · [Configuration](configuration.md) · [Scanning](scanning.md)

Clearance is a TypeScript ESM application. Source development uses Node.js 22.19
or newer; standalone builds use Bun. Gitleaks and TruffleHog remain separate
executables when their detectors are enabled.

## Install and check

```sh
npm ci
npm run check
```

`npm run check` runs type checking, Vitest, the TypeScript build, and the compiled
executable smoke checks. The scenario tests use real Gitleaks and TruffleHog
binaries on `PATH`; missing or unsupported binaries fail those tests.

| Command                    | Purpose                                        |
| -------------------------- | ---------------------------------------------- |
| `npm run dev -- --help`    | Run the CLI from TypeScript                    |
| `npm test`                 | Run the default test suite                     |
| `npm run typecheck`        | Check TypeScript without emitting files        |
| `npm run build`            | Build the Node.js CLI in `dist/`               |
| `npm run build:executable` | Build `dist/clearance` using Bun               |
| `npm run check:executable` | Build and smoke-test the standalone executable |
| `npm run format`           | Check formatting                               |
| `npm run format:fix`       | Apply formatting                               |

The standalone executable embeds native/Gitleaks policy files, uses the system
CA store, and disables dotenv and bunfig autoload. It needs no Node.js or Bun
interpreter at runtime. It still launches enabled external scanners/processors.

## Test coverage

With built-in configuration defaults, the suite does not call live models or
credential-verification services. Validator tests use a scripted runtime;
TruffleHog runs with verification disabled. Scenario helpers use normal configuration
layers, so run them without system/environment overrides that enable model stages.
Fixtures use invented values and temporary repositories, not real credentials.

| Area                | Tests cover                                                         |
| ------------------- | ------------------------------------------------------------------- |
| Configuration       | File layering, environment/CLI overrides, detector setup            |
| Inventory           | Includes/excludes, nested paths, archives, binary skips, roots      |
| Adapters            | Current and historical scanner output, versions, process limits     |
| Findings            | Evidence, correlation, PEM identity, allowlists, test-path policy   |
| LLM validation      | Structured verdicts, repairs, tool reads, timeouts, traces          |
| External processors | Wire validation, exact matching, process errors, coverage, progress |
| Output              | Human/JSON results, report toggles, raw values, live findings       |
| Compiled CLI        | Packaged policy, independent process invocation, stdout flushing    |

The `test/scenarios/` cases E1–E17 exercise complete scans: clean trees, current
and removed credentials, history, multiple roots, inclusion filters, allowlists,
scripted model verdicts, unsupported tools, and report content. Unit fixtures for
scanner parsers live under `test/fixtures/scanners/`.

Useful focused commands:

```sh
npm test -- test/classifier-example.test.ts
npm test -- test/no-report.test.ts test/live-findings.test.ts
npm test -- test/scenarios/e9-history-removed.test.ts
```

## Optional live-model test

The live test is opt-in and reads the normal configuration layers:

```sh
CLEARANCE_LIVE_LLM=1 \
CLEARANCE_LIVE_LLM_MODEL=your-model-id \
CLEARANCE_CONFIG=/path/to/config.toml \
npm test -- test/scenarios/live.test.ts
```

Supply your own endpoint and credentials outside the repository. A live-model
result measures that provider's behavior on synthetic input; it is separate from
the deterministic suite and is not run by default.

## Source map

| Location                                                                                   | Responsibility                                |
| ------------------------------------------------------------------------------------------ | --------------------------------------------- |
| [`src/cli-parse.ts`](../src/cli-parse.ts), [`src/config.ts`](../src/config.ts)             | CLI and configuration                         |
| [`src/scan.ts`](../src/scan.ts), [`src/walk.ts`](../src/walk.ts)                           | Orchestration and inventory                   |
| [`src/native/`](../src/native/), [`src/scanners/`](../src/scanners/)                       | Native and external scanner adapters          |
| [`src/classifier/`](../src/classifier/)                                                    | Generic executable classification integration |
| [`src/evidence.ts`](../src/evidence.ts), [`src/cluster.ts`](../src/cluster.ts)             | Source evidence and correlation               |
| [`src/suppress.ts`](../src/suppress.ts), [`src/test-fixtures.ts`](../src/test-fixtures.ts) | Allowlisting and fixture outcome policy       |
| [`src/llm/`](../src/llm/)                                                                  | Finding validation and traces                 |
| [`src/report/`](../src/report/), [`src/outcome.ts`](../src/outcome.ts)                     | Public results, reports, and exit status      |
| [`src/types.ts`](../src/types.ts)                                                          | Internal result types                         |

The documentation describes current behavior. Known boundaries are listed with
the relevant feature, including [scan coverage](scanning.md#current-limitations)
and [configuration fields with limited effect](configuration.md#settings-with-limited-effect).
