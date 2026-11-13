# Validation

larc-seraph v0.1.0. Author: Kevin Francis Tan / Light Architects. Date: 2026-11-13.

This file is the methodology and the results. A green test run proves the fixtures, the conversions, and this corpus. It does not prove a false-positive rate on a fleet we have not seen.

## What was run

| Gate | Result |
| --- | --- |
| pytest fixture truth table | Pass. Each positive matches only its rule. Each negative and the known-good set matches nothing. |
| Sigma `sigma check --fail-on-issues` | Pass, with the D3FEND tag validator excluded. This pack has no D3FEND tags, and that validator downloads an ontology before it looks at the namespace. ATT&CK tags are still checked. |
| pySigma conversion | Pass. Lucene via `pipelines/ecs-macos.yml` and Splunk via `pipelines/splunk-macos.yml`. Output is in `rules/converted/`. |
| Telemetry round-trip | Pass. Every Sigma rule has eslogger, ECS, and osquery samples, positive and negative. `larc_seraph.translate` maps them onto the field contract and the evaluator agrees with the fixture. |
| libyara | Pass. `yara-python` compiles the set. |
| yara-x 1.23.0 | Pass. `yr compile rules/yara` exits 0 with no warning text, including no slow-rule warning. |
| Wide-tree speed | Pass. 400 benign Markdown files scanned in the unit test in under 10 seconds. The corpus scan below is the larger number. |
| Benign corpus | Pass against the allowlist. 15615 files in 1.0 seconds. Three hits, all allowlisted. No other rule fired. |
| Metadata | Pass. Author is Kevin Francis Tan. Date, references, ATT&CK, severity, and false-positive notes are required by the test. Sigma UUIDs and YARA ids are unique. |
| Evasion matrix | Pass. `validation/evasion-matrix.yml` is executed by pytest. Misses are asserted, not ignored. |

## Benign corpus

`tools/fp_scan.py` clones, downloads, and scans. It does not execute the files. Cache is `validation/cache/` and is not committed.

Trees included in the run that produced the numbers above:

- `modelcontextprotocol/servers` (MCP server READMEs and configs)
- `typicode/husky` and `pre-commit/pre-commit-hooks` (Git hooks)
- `github/gitignore`
- `openai/codex` and `google-gemini/gemini-cli` (agent instruction and MCP docs)
- `requests` and `PyYAML` wheels, plus the installed PyYAML tree
- npm packs of `lodash` and `express`

Homebrew cask Ruby files were not a separate tree. The servers and gemini-cli trees contain the plist-like and MCP material we could fetch from public git. Apple's own on-disk LaunchAgents were not available in this Linux build environment, so they are not in the count. That is a hole in the corpus, not a claim that Apple plists were scanned.

### Hits

| Rule | Count | What the file actually is |
| --- | --- | --- |
| `SERAPH_MCP_Remote_Npx` | 1 | `gemini-cli` unit test that embeds `@playwright/mcp@latest` as sample config. The rule is doing what it says. |
| `SERAPH_MCP_Unpinned_Package` | 2 | Official `servers` READMEs for time and fetch, which show `uvx mcp-server-time` and `uvx mcp-server-fetch` with no version. |

No other rule matched. `node_modules` content from the two npm packs and the Python trees matched nothing.

The allowlist is `validation/fp-allowlist.txt`. A new hit that is not on that list fails the script.

## Evasion

Caught, after the cheap fixes in this version: extra spaces around a pipe, `wget` and `fetch` in place of curl, `/usr/bin/curl`, macOS `base64 -D`, `urllib.request.urlopen` next to `exec`, dictionary `KeepAlive`, a quoted `git+` URL, `@latest` in a test string, Terminal as the parent, and one zero-width code point inside the confirmation phrase.

Not caught, on purpose or because the fix would be a different detector:

| Case | Why it misses |
| --- | --- |
| Fetch tool named only by a variable | The bytes never contain `curl` or `wget`. |
| `base64` split as `ba''se64` | The literal is broken. |
| Package name built by concatenation | There is no single JSON string to judge. |
| Remote URL more than 160 bytes after `npx`, or an unquoted `https://` used only as a Markdown link | Tightened so READMEs that link the word npx do not match. |
| Bare `/tmp` with no further path segment | A directory grant, not a launched binary. |
| Custom secret variable name | The name list is finite. |
| Zero-width mark between every letter | One mark is tolerated. A mark per letter is not. |
| U+200B with no other hidden-text signal | Too common to treat as instructions. |
| `KeepAlive` integer 1 | Not a boolean and not a dictionary. |
| Host-key option only in `~/.ssh/config` | The plist does not contain it. |
| Hook with no shebang | Out of scope for that rule. |
| Parent recorded only as a pid | `ParentImage` is empty. |
| Piped shell whose parent is launchd | The plist rules cover that stage. |
| `authorized_keys.bak`, Fish `config.fish` | Not in the path lists. |
| `-R` glued to its value | The rule wants a space-delimited flag. |

## ATT&CK and ATLAS

| ID | ATT&CK | ATLAS, where it fits |
| --- | --- | --- |
| SERAPH-YARA-001 | T1059.004 | |
| SERAPH-YARA-002 | T1059.004, T1105 | |
| SERAPH-YARA-003 | T1027, T1140, T1059.004 | |
| SERAPH-YARA-004 | T1195.002 | |
| SERAPH-YARA-005 | T1552.001, T1567 | |
| SERAPH-YARA-006 | T1027 | AML.T0051 prompt injection, as the hiding channel |
| SERAPH-YARA-007 | T1567, T1562.001 | AML.T0051. T1562.001 is an approximation for "stop asking". |
| SERAPH-YARA-008 | T1543.001, T1543.004, T1059.004 | |
| SERAPH-YARA-009 | T1572, T1021.004, T1543.001 | |
| SERAPH-YARA-010 | T1059.004, T1546 | |
| SERAPH-YARA-016 | T1195.002 | |
| SERAPH-SIGMA-011 | T1098.004 | |
| SERAPH-SIGMA-012 | T1546.004 | |
| SERAPH-SIGMA-013 | T1543.001, T1543.004 | |
| SERAPH-SIGMA-014 | T1572, T1021.004 | |
| SERAPH-SIGMA-015 | T1059.004, T1105 | |
| SERAPH-SIGMA-016 | T1059.004, T1105 | |

Sigma tags are only the ATT&CK namespace. ATLAS ids are references and this table. pySigma rejects an `atlas` tag namespace.

## Telemetry mapping

| Contract field | eslogger | ECS | osquery |
| --- | --- | --- | --- |
| Image | `event.exec.target.executable.path` on exec, else `process.executable.path` | `process.executable` | `path` |
| CommandLine | `event.exec.args` joined with spaces | `process.command_line` | `cmdline` |
| ParentImage | `process.executable.path` on exec (the actor), else `process.parent.executable.path` | `process.parent.executable` | `parent_path` if a join added it |
| TargetFilename | create, write, or rename destination path | `file.path` | `target_path` |
| User | `process.user_name` | `user.name` | `username` |

Joining eslogger args with spaces drops quoting. A command whose only copy of a pipe character lived inside quotes that the collector already split can still match, which is what the samples do. A collector that drops args entirely will not fire command-line rules.

## What this does not cover

- Rephrased instructions that avoid the phrase list.
- Memory-only tradecraft and encrypted blobs that are never decoded in the file.
- A full macOS image of `/System/Library/LaunchAgents`. This environment is Linux.
- Every EDR schema. ECS and the eslogger shape we documented are the two we convert and test. osquery is the third normalizer.
- A claim that the three allowlisted corpus hits are the only benign hits that will ever occur.
