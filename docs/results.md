# Reading results and reports

[Overview](../README.md) · [Configuration](configuration.md) · [Scanning](scanning.md)

Clearance returns one outcome for the run. Findings, coverage gaps, and detector
failures remain separate in the result so you can see why a run was not cleared.

## Outcomes and exit codes

| Outcome      | Exit | Meaning                                                                  |
| ------------ | ---: | ------------------------------------------------------------------------ |
| `clean`      |    0 | No open findings or recorded coverage gaps remain                        |
| `findings`   |    1 | Open findings are below the configured severity threshold                |
| `denied`     |    2 | At least one open finding meets or exceeds `report.failOn`               |
| `incomplete` |    2 | Coverage has gaps, with no finding taking precedence as `denied`         |
| `error`      |    3 | Configuration, an enabled detector, or another required operation failed |

Precedence is `error` → `denied` → `incomplete` → `findings` → `clean`.
The severity order is `low`, `medium`, `high`, `critical`; the default threshold
is `high`.

A `denied` result can also have incomplete coverage. Check `coverage` and
`detectors`, not only the headline. A `clean` result reflects configured scope
and the [current scanning limitations](scanning.md#current-limitations).

## Output channels

| Channel          | Default behavior                                          | Controls                                                               |
| ---------------- | --------------------------------------------------------- | ---------------------------------------------------------------------- |
| stdout           | Human summary                                             | `--json` selects the full public JSON result                           |
| stderr           | Progress and raw live findings on an interactive terminal | `--progress` forces them; `--quiet` hides them; warnings/errors remain |
| Report files     | JSON, Markdown, and HTML                                  | `--no-report` disables files; `--output` selects their directory       |
| Validator traces | Disabled                                                  | `--llm-trace` enables separate JSONL and HTML diagnostic files         |

```sh
# Human result without report files
clearance --no-report /path/to/project

# Machine-readable result without progress or report files
clearance --json --no-report --quiet /path/to/project > result.json

# Show ongoing work and original matches in the terminal
clearance --progress /path/to/project
```

Progress lines use fixed-width UTC timestamps: `YYYY-MM-DD HH:mm:ss UTC`.
Native hits appear as found, external scanner hits after each root completes,
and classifier hits after each file completes. Validator verdicts appear by batch.
Live hits are unverified and can repeat across detectors; the final result applies
correlation, validation, suppression, and fixture policy.

`--quiet` does not hide the final result. `--json` normally disables automatic
progress, but `--progress --json` keeps progress on stderr and JSON on stdout.
If redirecting JSON into a scanned directory, exclude that destination or write
outside the scan roots to avoid scanning the output itself.

## Original values and privacy

Reports and JSON stdout omit extracted candidates and source lines by default.
Use `--include-raw` or `[report].includeRaw = true` when those values are needed
for remediation.

| Data                                                  | Where it appears                                                                                    |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Exact candidate                                       | Cluster `raw`, only with raw output enabled and `evidence = "exact"`                                |
| Matched source line                                   | Cluster `match`, only with raw output enabled; can exist for inexact findings                       |
| Relative finding paths, rules, descriptions, verdicts | Public results in either mode                                                                       |
| Root paths                                            | JSON preserves the supplied root path, which may be absolute; the human summary uses resolved paths |
| Raw live matches                                      | stderr when progress is enabled, independently of `--include-raw`                                   |
| Model input and full traces                           | Original evidence; not controlled by the report raw-output setting                                  |

Occurrence rows do not publish their internal `candidate`, `evidenceText`, or
`matchLine` fields. The report layer does not copy raw scanner JSON. This is not
a general anonymizer: filenames, user-supplied paths, rule descriptions, and other
metadata can still identify a project.

Live text is quoted with control characters escaped. Full validator traces can
contain original evidence and model output; see [tracing](validation.md#diagnostic-traces).

## Report files

Reports default to `./clearance-report`, resolved from the process working
directory rather than the first scan root.

| File            | Contents                                         |
| --------------- | ------------------------------------------------ |
| `manifest.json` | Full public result, schema `clearance.report/v1` |
| `report.md`     | Human-readable findings and coverage             |
| `report.html`   | Standalone HTML view with no external assets     |

All three files are written when reporting is enabled, even if `report.formats`
is set to a smaller list. Each file is replaced using a temporary file and rename;
the three files are not published as one atomic transaction.

Reports are written for completed scans, including denied and scan-time error
results. CLI parsing and configuration-loading failures do not create reports.
Errors after successful configuration loading, including invalid roots or all
detectors disabled, honor `report.enabled`.
CLI syntax errors produce stderr diagnostics only; errors after valid argument
parsing also produce the selected stdout result.

`--no-report` does not create, overwrite, or delete report files, and does not
reserve an otherwise unused output directory. Report directories are excluded
from scans when reporting is enabled. Explicit validator tracing remains
independent; a trace inside the report directory also reserves that directory.

## JSON result reference

`--json` uses the same public representation as `manifest.json` in either report
mode. The main fields are:

| Field                           | Contents                                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `schemaVersion`                 | `clearance.report/v1`                                                                            |
| `outcome`, `exitCode`, `failOn` | Decision and threshold                                                                           |
| `startedAt`, `finishedAt`       | Run timestamps                                                                                   |
| `roots`                         | `rootId` and supplied `path` for each root                                                       |
| `detectors`                     | Stage name, enabled state, status, optional version/error                                        |
| `classifier`                    | Optional policy digest and per-file coverage                                                     |
| `llm`                           | Optional validator model/API and stage status                                                    |
| `occurrences`                   | Individual detector hits and source locations                                                    |
| `clusters`                      | Correlated findings, effective policy state, and optional verdicts                               |
| `coverage`, `skipped`           | Recorded gaps and skipped paths                                                                  |
| `summary`                       | Walk counts: walked, scannable, skippedHarmless, excludedByConfig, archive, oversize, unreadable |
| `errors`                        | Run-level errors                                                                                 |

Detector states are `completed`, `failed`, and `skipped`; the external classifier
also uses `partial`. A classifier file has `completed`, `empty`, `excluded`, or
`failed` status. A file failure such as `child-provider_unavailable` means that
file's classification did not complete; it does not mean the file is clean.

Finding rows use a `rootId` and relative `path`. Occurrences also include the
scanner, rule, category, severity, line range, extraction status, and source:
`workingTree` or `git` with a commit. Classifier locations include half-open UTF-8
byte offsets; columns use UTF-16 code units.

Cluster fields distinguish:

- `severity` from `effectiveSeverity`, which incorporates applied policy.
- `effectiveStatus`: `open`, `suppressed`, or `policy_excluded`.
- `presence`: `current`, `historical`, or `current_and_historical`.
- `foundBy` and `notFoundBy`: detector corroboration, not confidence scores.
- `llm`: the actual verdict, confidence, rationale, and whether it is advisory.

Human reports separate current and historical-only clusters. History sections
are omitted when no history stage ran and there are no historical-only findings.
`--show-history-commits` expands sampled commit details.

The complete field definitions are in [`types.ts`](../src/types.ts), with the
public projection in [`report/public.ts`](../src/report/public.ts). The library's
internal `ScanResult` includes fields such as artifact paths that the public JSON
projection does not include.

## Diagnosing failures

Inspect `detectors[].status` and `error` for stage failures. For external
classification, also inspect `classifier.files[].status` and `reason`: the
stage can be `partial` while individual files have different failure causes.

Common detector diagnostics include:

| Code                                                             | Meaning or next check                                                                       |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `missing-binary`                                                 | Install the selected scanner or change its `bin` path                                       |
| `unsupported-version`                                            | Version is unsupported, or the version probe failed or timed out; check the binary manually |
| `missing-admin-config`                                           | Check the selected Gitleaks configuration/ignore files or TruffleHog configuration file     |
| `timeout`                                                        | The scanner invocation exceeded its configured deadline                                     |
| `output-limit`, `finding-limit`                                  | A configured scanner output or finding bound was exceeded                                   |
| `adapter-error`                                                  | Scanner execution or output failed; for `native`, rule loading failed (see `errors[]`)      |
| `unparseable`                                                    | The scanner output could not be parsed                                                      |
| `archive-member`, `unredacted-secret`, `unexpected-git-metadata` | Output violated the adapter's input contract                                                |
| `environment-unavailable`                                        | A classifier environment mapping names an unset parent variable                             |
| `classification-incomplete`                                      | At least one required classifier file did not complete                                      |

Disabled detectors have `enabled: false` and `status: "skipped"`. Enabled but
skipped detectors can have reasons such as `bare-repository`,
`not-a-git-repository`, or `git-unavailable`. These describe scope or availability,
not a positive finding.

Classifier rows with `status: "excluded"` reuse inventory reasons such as
`archive`, `oversize`, `unreadable`, `harmless`, or `symlink-escape`.
The following reasons describe failed classification:

| Reason                                                                        | Meaning                                                                                      |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `snapshot-unavailable`                                                        | Original file snapshot could not be captured or used                                         |
| `drift`                                                                       | Content or file identity changed                                                             |
| `non-text`, `invalid-utf8`                                                    | File text did not meet input requirements                                                    |
| `file-limit`, `input-limit`, `output-limit`, `stderr-limit`                   | A byte bound was exceeded                                                                    |
| `resolution-limit`, `finding-limit`                                           | Source matching or finding expansion exceeded a bound                                        |
| `timeout`, `cancelled`                                                        | Processing timed out or was cancelled                                                        |
| `launch-failed`, `input-failed`, `output-failed`, `process-failed`            | Subprocess startup, I/O, or exit failed                                                      |
| `invalid-response`, `invalid-finding`, `invalid-vocabulary`, `invalid-source` | Returned findings failed validation                                                          |
| `environment-unavailable`, `classification-failed`                            | Setup was unavailable or failure had no more specific public code                            |
| `child-<code>`                                                                | The executable returned a recognized [error envelope](external-processors.md#error-response) |

For example, `child-provider_unavailable` identifies a failure reported by the
processor. It does not identify a secret or establish why the provider was
unavailable. Keep the failed file's coverage distinct from successful files.

The current producers of these diagnostics are the
[Gitleaks adapter](../src/scanners/gitleaks.ts),
[TruffleHog adapter](../src/scanners/trufflehog.ts),
[scanner process wrapper](../src/scanners/process.ts),
[classifier scanner](../src/classifier/scanner.ts), and
[classifier process wrapper](../src/classifier/process.ts).

## Suppression and fixture policy

String/regex allowlists operate on exact extracted candidates after correlation.
When an exact member is allowlisted, the correlated cluster and its members are
suppressed. Inexact or unavailable evidence cannot independently match an allowlist.
Suppressed clusters skip LLM validation and do not count toward the outcome.

JSON retains suppressed clusters. Human reports hide their details unless
`--show-suppressed` is supplied, except for test-only clusters covered by the explicit fixture-exclusion policy,
which remain visible in their dedicated presentation. A path annotation alone
does not make suppressed details visible.

The LLM's `false_positive` verdict suppresses a finding only when
`llm.canOverride = true`. Otherwise it is advisory. Test-path exclusions are a
separate policy and never manufacture an LLM verdict.

## Test-fixture path context

Clearance labels likely test paths even when exclusions are disabled. Human
reports separate test-only clusters and label clusters that mix test and other
paths. A path hint does not prove a credential is fake.

```sh
# Still scan and validate test files, but exclude test-only findings from the outcome
clearance --exclude-test-fixtures /path/to/project
```

This option defaults to off. It changes the report's effective policy state after
screening; it does not remove files from native, external, history, or LLM inputs.
Mixed clusters still count, and coverage gaps or operational errors still block
clearance. Already-suppressed findings keep their suppression status.

| Matched path form                                         | Examples                                                 |
| --------------------------------------------------------- | -------------------------------------------------------- |
| Directory component, case-insensitive                     | `test`, `tests`, `__tests__`, `fixtures`, `__fixtures__` |
| Delimited `test` or `spec` marker with a source extension | `auth.test.ts`, `test_auth.py`, `auth_spec.rb`           |
| Delimited explicit `fixture` marker, any extension        | `data.fixture.json`, `fixture_data.yaml`                 |

It does not blanket-match `specs/`, `contest`, or `latest`. Bare filenames
`test.yaml`, `spec.yaml`, and `fixture.json` are not markers. Configuration/data
names such as `.env.test`, `application-test.properties`, `values-test.yaml`,
`appsettings.Test.json`, `openapi-spec.yaml`, `api.spec.json`, `pod-spec.yaml`, and
`package.spec` do not match the source-extension rule.

Recognized source extensions are:

```text
js jsx ts tsx mjs cjs mts cts py go rs java kt kts scala rb php swift
c cc cpp cxx h hpp cs fs fsx ex exs erl clj cljs cljc dart lua pl r jl sh
```

JSON annotations include `pathContext`, `testFixtureOccurrenceIds`,
`policyExcludedOccurrenceIds`, and `policyExclusion`. Fully excluded open clusters
become `effectiveStatus: "policy_excluded"`; the original LLM verdict remains
available alongside the policy annotation.
