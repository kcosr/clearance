# Configuration and command-line reference

[Overview](../README.md) · [Scanning](scanning.md) · [Results](results.md) · [LLM validation](validation.md)

Clearance accepts TOML configuration and command-line overrides. Start with a
small configuration containing only the settings you want to change; omitted
fields retain their defaults.

## Configuration precedence

Highest priority wins, field by field:

1. Command-line flags.
2. Environment variables.
3. The file selected by `--config PATH` or `CLEARANCE_CONFIG`.
4. `/etc/clearance/config.toml`, if present.
5. Built-in defaults.

Objects merge recursively. Arrays in configuration files replace the lower-priority
array. `--include` replaces `scan.include` the same way. Two flags append instead:
`--exclude` adds to `scan.exclude`, and `--suppress-string` adds to
`suppress.strings`.

```sh
clearance --config /path/to/my-config.toml /path/to/project
CLEARANCE_CONFIG=/path/to/my-config.toml clearance /path/to/project
```

The system file is a convenient default, not enforced policy. A missing system
file is allowed; a missing or invalid explicitly selected file is an error.
Clearance does not discover home-directory configuration or automatically load
`.clearance.toml` from a scanned directory.

Keep scanner policies, rule directories, validator instruction files, and the external
classifier executable outside scan roots. Clearance rejects those paths when they resolve
inside a root. When the external classifier is enabled, the selected Clearance
configuration files must also be outside the scan roots.

## Environment variables

| Variable                            | Setting                                                    |
| ----------------------------------- | ---------------------------------------------------------- |
| `CLEARANCE_CONFIG`                  | Explicit TOML file, unless `--config` is supplied          |
| `CLEARANCE_OUTPUT`                  | Report directory                                           |
| `CLEARANCE_FAIL_ON`                 | Severity threshold: `low`, `medium`, `high`, or `critical` |
| `CLEARANCE_LLM_TRACE`               | Validator trace path                                       |
| `CLEARANCE_LLM_TRACE_DETAIL`        | `metadata` or `full`                                       |
| Variable named by `model.apiKeyEnv` | Model authentication credential                            |

The compiled executable does not autoload `.env` or `bunfig.toml`.

## Common command-line options

```text
clearance [paths...] [flags]
```

With no paths, Clearance scans the current directory. Multiple paths produce one
combined result. Each path must be a directory; duplicate or overlapping roots
are rejected. Use `--` before paths that start with `--`.

| Option                                                   | Effect                                                                 |
| -------------------------------------------------------- | ---------------------------------------------------------------------- |
| `--config PATH`                                          | Select a TOML file                                                     |
| `--include GLOB`                                         | Restrict eligible file paths; repeatable                               |
| `--exclude GLOB`                                         | Exclude paths; repeatable                                              |
| `--native` / `--no-native`                               | Enable or disable native rules                                         |
| `--gitleaks` / `--no-gitleaks`                           | Enable or disable Gitleaks working-tree scanning                       |
| `--trufflehog` / `--no-trufflehog`                       | Enable or disable TruffleHog working-tree scanning                     |
| `--gitleaks-history` / `--no-gitleaks-history`           | Independently control Gitleaks history scanning                        |
| `--trufflehog-history` / `--no-trufflehog-history`       | Independently control TruffleHog history scanning                      |
| `--classifier` / `--no-classifier`                       | Control the configured [external processor](external-processors.md)    |
| `--llm` / `--no-llm`                                     | Control finding validation                                             |
| `--llm-override` / `--no-llm-override`                   | Let validator verdicts affect findings, or keep them advisory          |
| `--llm-mode validate`                                    | Select the supported validation mode                                   |
| `--model NAME`                                           | Override `model.model`                                                 |
| `--reasoning VALUE`                                      | Override the provider reasoning setting                                |
| `--chat-template-thinking true\|false`                   | Set the Chat Completions thinking option                               |
| `--llm-instructions PATH`                                | Select validator instructions                                          |
| `--on-archive skip\|incomplete`                          | Set archive coverage policy                                            |
| `--on-opaque skip\|incomplete`                           | Set archive, oversize, and unreadable-file policies together           |
| `--suppress-string STRING`                               | Add an exact candidate allowlist entry; repeatable                     |
| `--exclude-test-fixtures` / `--no-exclude-test-fixtures` | Control test-path exclusions from the outcome; files are still scanned |
| `--fail-on SEVERITY`                                     | Set the threshold for a `denied` result                                |
| `--report` / `--no-report`                               | Enable or disable report files                                         |
| `--output DIR`                                           | Set the report directory                                               |
| `--json`                                                 | Print the complete public result as JSON                               |
| `--include-raw` / `--no-include-raw`                     | Control original values in reports and JSON stdout                     |
| `--progress` / `--quiet`                                 | Show or hide progress and raw live findings on stderr                  |
| `--show-suppressed`                                      | Show suppressed rows in human reports                                  |
| `--show-history-commits`                                 | Expand history commit details in human reports                         |
| `--llm-trace PATH`                                       | Write validator JSONL and HTML traces                                  |
| `--llm-trace-detail metadata\|full`                      | Select trace detail                                                    |
| `--version`, `--help`                                    | Print version or help and exit                                         |

For paired switches, the last occurrence wins. `--json` controls the stdout
format independently of report files and progress.

## File selection defaults

| `[scan]` setting                          | Default                                              | Meaning                                                               |
| ----------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------- |
| `include`                                 | `[]`                                                 | All eligible paths                                                    |
| `exclude`                                 | `.git/**`, `node_modules/**`, `dist/**`, `.cache/**` | Paths omitted from the inventory and filtered out of scanner findings |
| `maxFileBytes`                            | `1048576`                                            | One MiB; `0` disables this inventory/evidence size cap                |
| `maxDepth`                                | `32`                                                 | Directory traversal limit, with the root at depth 1                   |
| `onUnreadable`, `onOversize`, `onArchive` | `incomplete`                                         | Record a coverage gap; `skip` records a skipped file instead          |
| `excludeTestFixtures`                     | `false`                                              | Whether test-only findings are excluded from the outcome              |

`skipExtensions` contains common images, fonts, and media; SVG remains text.
`archiveExtensions` contains `.zip`, `.tar`, `.tgz`, `.gz`, `.7z`, `.rar`, `.jar`,
`.war`, and `.whl`. Both lists are configurable. See the full lists in
[the example configuration](../examples/config.toml) and the
[current coverage limitations](scanning.md#current-limitations).

## Detector settings

| Section                  | Defaults and supported settings                                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `[detectors.native]`     | `enabled = true`; `rulesD` selects a directory of TOML rules                                                                 |
| `[detectors.gitleaks]`   | `enabled = true`, `history = false`, `bin = "gitleaks"`; `config` and `ignore` select policy files                           |
| `[detectors.trufflehog]` | `enabled = true`, `history = false`, `bin = "trufflehog"`; optional `config`, `includeDetectors`, and `excludeDetectors`     |
| `[detectors.classifier]` | Disabled by default; see [external processors](external-processors.md) for executable, arguments, policy, and process limits |

Built-in native and Gitleaks policies come from the installation's `examples/`
directory in a source install and are embedded in the compiled executable.
Custom Gitleaks configuration and ignore files must both be present when selected.
TruffleHog's configuration is optional; empty detector lists use its built-ins.

The complete [example TOML](../examples/config.toml) illustrates a system install
with policy paths under `/etc/clearance`. Those files must be installed there or
the example paths changed. Copying it unchanged is not required to use defaults.

At least one detector must be enabled. The `[llm]` validator alone does not count
as a detector because it only evaluates existing findings.

## Reporting and suppression

```toml
[report]
enabled = true
outputDir = "./clearance-report"
failOn = "high"
includeRaw = false
progress = "auto"
```

`progress` accepts `auto`, `on`, or `off`. Automatic progress is enabled when
stderr is a terminal and `--json` is not selected. Quiet mode still prints the
final result and warnings/errors. See [output channels](results.md#output-channels).

```toml
[suppress]
strings = []
patterns = []
ignoreCase = false
```

Suppressions match extracted candidates across detectors. `patterns` uses
JavaScript regular expressions, and `ignoreCase` applies to both lists. Suppressed
findings remain in JSON; `--show-suppressed` shows their human-report details.
See [suppression and fixture policy](results.md#suppression-and-fixture-policy).

## Scanner resource limits

| `[limits]` setting |  Default |
| ------------------ | -------: |
| `scannerTimeoutMs` |   120000 |
| `versionTimeoutMs` |     5000 |
| `maxStdoutBytes`   |  8000000 |
| `maxReportBytes`   | 16000000 |
| `maxFindings`      |    10000 |

These bounds govern external scanner calls and their parsed reports. The external
classifier has separate limits, including a remaining finding allowance after
other detectors. A limit failure is reported, not interpreted as an empty scan.

## Settings with limited effect

Some accepted fields currently have narrower effects than their names suggest:

| Setting                 | Current behavior                                                                                    |
| ----------------------- | --------------------------------------------------------------------------------------------------- |
| `report.formats`        | Accepted, but enabled reporting always writes JSON, Markdown, and HTML                              |
| `model.contextWindow`   | Accepted, but not used to calculate validator batch sizes                                           |
| `llm.batch.concurrency` | Accepted, but validator batches run sequentially                                                    |
| `llm.partialOnTimeout`  | Does not discard completed verdicts when false; see [timeouts](validation.md#failures-and-timeouts) |

Model transport, prompts, batching, and traces are covered in
[LLM validation](validation.md). The complete configuration schema and defaults
are in [`src/config.ts`](../src/config.ts).
