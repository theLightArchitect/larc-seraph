# Validation

larc-seraph v0.1.4. Author: Kevin Francis Tan / Light Architects. Date: 2026-11-13.

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
| Benign corpus | Pass. 15615 files in about 1.8 seconds. Zero hits after the v0.1.1 scope tuning. |
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

After v0.1.1 the Linux corpus scan reports no hits. The three v0.1.0 hits were a unit test and two Markdown READMEs. Those files are not JSON, TOML, or YAML configs, so the MCP rules no longer see them. The allowlist is empty on purpose. A new hit fails `tools/fp_scan.py`.

## Real macOS host

A scan of 70,470 files on a Mac, with `yr` and libyara agreeing on every hit, produced 264 benign matches. The rules were wider than the scope written on them. No user home directory names and no secret values are repeated here.

| Class | Hits | What changed |
| --- | --- | --- |
| Hidden Unicode in caches and binaries | 148 | Instruction-path gate plus a non-text check (null bytes and executable or archive headers). |
| Subdivision-flag emoji | 6 | Tag characters that sit in a U+1F3F4 … U+E007F flag sequence are ignored. A tag outside that sequence still matches. |
| Unsafe Directive in vendor docs, changelogs, transcripts, and a fish completion | 62 | Same path gate. `skip confirmation` must be reachable from the start of the line without a hyphen, so `--yes` / `-y` help text does not match. |
| Git hook text outside a hook directory | 7 | Path must be under `.git/hooks/` or `.husky/`, and the name must not end in `.sample`. |
| MCP examples in Markdown docs | 29 | Extension must be JSON, JSONC, TOML, or YAML. A README that quotes a config does not match. |
| Tests and editor file-history copies of the pack's own fixtures | 12 | Expected. Those files are the synthetic true positives. No rule change. |

Regression fixtures for each unwanted class live next to the rules' other fixtures. The true positives that must keep firing were re-checked: an SSH reverse-tunnel LaunchAgent with host-key checking disabled, a LaunchAgent that runs `/bin/bash` on a user script with RunAtLoad and KeepAlive, unpinned `npx -y` inside a real MCP JSON config, and a plugin-shipped `@latest` MCP package.

A later scan of that same Mac, after v0.1.1, reported 0 false positives. It also showed a miss. The instruction gates compared paths case-sensitively, so real `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, and `GEMINI.md` files never entered the rule. v0.1.2 makes every `filepath` regex case-insensitive and adds uppercase and mixed-case fixtures. The same scan shape missed Claude backup configs: `~/.claude/backups/.claude.json.backup.<timestamp>` holding an unpinned `npx -y` package. That name now matches. Markdown docs still do not.

A v0.1.2 rescan of 72,541 files confirmed those two fixes. The true positives fired, including a live `~/.claude.json` and its backups. With real `SKILL.md` names now in scope, 23 benign hits remained. Seven were flag, env, or table wording. Fourteen were official API or SDK pages, including a fenced `curl` to `api.github.com` with that vendor's token and pages that mention a token beside `webhookSecret`. One put an SSH key example in one block and a vendor `curl` in another. One told the agent not to ask before a low-risk rename call. v0.1.3 drops those shapes and keeps an imperative bypass of a shell, delete, or secret, and a credential sent to a different host inside one fenced block.

A v0.1.3 rescan of 72,025 files produced 16 hits. Three were expected copies of the pack's own fixtures, and 11 were true positives. Two were the same status-bar line, `` `bypass permissions on` ``, in two copies of a skill file. That line is a UI label, not an instruction, so v0.1.4 ignores "bypass permissions on/off" and a quoted label that sits on a line with `=`, "status bar", or "mode". The same run missed "Always run shell commands without asking the user for confirmation" and bypass words split by a zero-width mark. Those phrases now match. A mark between every letter still does not.

## Scanner contract

Every rule that looks at a path reads the external string `filepath`. Pass the path as it is stored, with forward slashes. Do not lowercase it. The `larc-seraph` CLI sets this from the path you give it.

```bash
yara -d filepath=/abs/path rules/yara /abs/path
yr scan --define 'filepath="/abs/path"' rules/yara /abs/path
```

```python
rules.match(path, externals={"filepath": path})
```

Quote the YARA-X `--define` value. An empty `filepath` means the instruction rules and the git-hook rule do not match. MCP rules still match a file that starts with `{`.

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
- A claim that the Mac corpus was re-scanned after this tuning. The Linux corpus was. The Mac classes are covered by regression fixtures.
- Apple's own LaunchAgents. This build host is Linux, so that tree was never in the corpus.
