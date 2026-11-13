![larc-seraph — detection content for agent tooling on the workstation](docs/assets/banner.svg)

# larc-seraph

[![CI](https://github.com/theLightArchitect/larc-seraph/actions/workflows/test.yml/badge.svg)](https://github.com/theLightArchitect/larc-seraph/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/theLightArchitect/larc-seraph)](https://github.com/theLightArchitect/larc-seraph/releases)
[![Code license](https://img.shields.io/badge/code-Apache--2.0-blue)](LICENSE)
[![Rule license](https://img.shields.io/badge/rules-DRL%201.1-blue)](LICENSE.rules)

Defensive detection content for AI-agent tooling on developer workstations, written by Kevin Francis Tan / Light Architects ([lightarchitects.ai](https://lightarchitects.ai)).

The release badge stays empty until a maintainer pushes a `vX.Y.Z` tag. v0.1.9 prepares that workflow. It does not publish the release by itself.

Rule IDs stay in the `SERAPH-YARA` and `SERAPH-SIGMA` series. The pack name is larc-seraph.

YARA rules for the files an agent trusts. Sigma rules for the macOS events those files become. Synthetic fixtures and a pytest harness so a match means what the catalog says it means.

The docs site is [docs/index.html](docs/index.html). The threat model and field contract are [docs/content/threat-model.md](docs/content/threat-model.md).

## What this is

Eighteen experimental rules:

| ID | Engine | What it watches |
| --- | --- | --- |
| `SERAPH_MCP_Launch_From_Temp` | YARA | MCP command launched from a temp or cache path |
| `SERAPH_MCP_Curl_Pipe_Shell` | YARA | MCP config pipes a fetch into a shell |
| `SERAPH_MCP_Encoded_Exec` | YARA | MCP config decodes into a shell or eval |
| `SERAPH_MCP_Remote_Npx` | YARA | npx or uvx from a URL, `github:` specifier, or `@latest` |
| `SERAPH_MCP_Unpinned_Package` | YARA | npx or uvx package with no numeric version |
| `SERAPH_MCP_Secret_Exfil` | YARA | A token variable interpolated into a URL or a fetch |
| `SERAPH_Instruction_Hidden_Unicode` | YARA | Unicode tags or bidi overrides in instruction files |
| `SERAPH_Instruction_Unsafe_Directive` | YARA | Confirmation bypass, or a credential path next to a sink |
| `SERAPH_LaunchPlist_Writable_Interpreter` | YARA | RunAtLoad, KeepAlive, a shell, and a user-writable path |
| `SERAPH_LaunchPlist_SSH_Reverse_Tunnel` | YARA | Reverse SSH in a plist with host-key checking disabled |
| `SERAPH_Git_Hook_Suspicious_Exec` | YARA | Hook decodes into a shell, or posts a credential path |
| `SERAPH_MacOS_Agent_Writes_Authorized_Keys` | Sigma | Agent host writes `authorized_keys` |
| `SERAPH_MacOS_Agent_Modifies_Shell_RC` | Sigma | Agent host writes a user shell startup file |
| `SERAPH_MacOS_Interpreter_Drops_Launch_Plist` | Sigma | Interpreter writes a LaunchAgent or LaunchDaemon plist |
| `SERAPH_MacOS_SSH_Reverse_Lax_HostKey` | Sigma | ssh reverse forward with host-key checking disabled |
| `SERAPH_MacOS_Agent_Piped_Shell` | Sigma | Agent parent spawns a fetch or decode handed to a shell |
| `SERAPH_MacOS_Terminal_Piped_Shell` | Sigma | Terminal or iTerm parent spawns a fetch or decode handed to a shell |
| `SERAPH_MacOS_Node_Starts_AI_CLI_Skip_Permissions` | Sigma | node, npm, or npx starts an AI CLI with a skip-permission flag |

Each rule carries author, date (2026-11-13), ATT&CK mapping, severity, scope, and a false-positive note. Status is experimental.

## What this is not

This is not an EDR, a blocker, or a claim of coverage. It is not offensive tooling. Fixtures under `tests/fixtures/` are synthetic and inert, labelled `synthetic-benign`, and use `example.invalid` where a host appears. Do not execute them. A green test run proves the fixtures and the rule metadata. It does not prove a fleet false-positive rate.

Sigma rules assume a normalized macOS field contract (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`). They do not match raw Apple unified logs until a translator maps Endpoint Security events onto those names. The threat model states that limit in full.

`SERAPH-YARA-016` flags an unpinned registry package inside a JSON, TOML, or YAML MCP config. `@modelcontextprotocol`, `@anthropic`, and `@github` are allowlisted on that package entry. A numeric version on the package token is not a match, and a pin or an allowlisted package elsewhere in the file does not clear a second unpinned package. A Markdown README that only quotes the config is not a match.

`SERAPH-YARA-016` and the old `SERAPH-SIGMA-016` used the same number. The terminal piped-shell rule is now `SERAPH-SIGMA-017`. Its Sigma UUID did not change. `SERAPH-SIGMA-018` is the Nx s1ngularity CLI rule. The metadata check rejects a repeated three-digit number across the two families. Rule names stay `SERAPH_*`. Neo23x0-style category prefixes (`MAL_`, `HKTL_`) classify malware families. These rules detect config and process shapes, and the catalog id is already the `SERAPH` number, so this pack does not add a second prefix.

## Quick start

Python 3.11 or newer. A full `pytest` run also needs `yarac` 4.5.x and the yara-x `yr` CLI on `PATH`. Without them the fixture tests that only need `yara-python` still run, and the compile tests fail.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest
larc-seraph path/to/mcp.json
```

The scanner prints matches. It does not block, quarantine, or send telemetry.

How to run the metadata check, `sigma check`, the benign-corpus scan, and the doc generator is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Consume the rules

Pass `filepath` as the path is stored. Use forward slashes. Quote the yara-x define so the shell does not eat the quotes.

```bash
# Forge / no externals
yara rules/yara /abs/path
yr scan rules/yara /abs/path

# Path-scoped, when you know the path
yara -d filepath=/abs/path rules/path-scoped /abs/path
yr scan --define 'filepath="/abs/path"' rules/path-scoped /abs/path
```

```python
rules.match(path, externals={"filepath": path})
```

`larc-seraph path/to/AGENTS.md` sets that external itself.

Sigma rules match the normalized macOS field contract, not raw unified logs. Convert them with sigma-cli, or use the queries already in `rules/converted/`:

```bash
sigma convert -t lucene -p pipelines/ecs-macos.yml -od rules/converted/lucene -ot '{stem}.txt' rules/sigma
sigma convert -t splunk -p pipelines/splunk-macos.yml -od rules/converted/splunk -ot '{stem}.txt' rules/sigma
```

Lucene output uses Elastic Common Schema names (`process.executable`, `process.command_line`, `file.path`). Splunk output uses the names in `pipelines/splunk-macos.yml` (`process_path`, `parent_process_path`). A pipeline is required. The default sigma field names are not this pack's contract.

Tagged releases attach a zip and a tarball of the rules, the converted queries, `validation/fp-allowlist.txt`, and the license files, plus `SHA256SUMS`. Check the sums before you copy the rules into a product.

## Run the tests

```bash
pip install -e ".[test]"
pytest
python tools/check_rule_metadata.py
```

`pytest` compiles the YARA pack, checks every positive and negative fixture, evaluates the Sigma rules through pySigma's condition tree, and runs `sigma check --fail-on-issues`. The ATT&CK tag check downloads MITRE's published STIX once and caches it. `pytest` fails if `yarac` or `yr` is not installed.

Regenerate the HTML site after a rule or write-up change:

```bash
python -m larc_seraph.docsgen
python -m larc_seraph.docsgen --check
```

Open `docs/index.html` in a browser. It is a static site. No server is required. The visual language is Galaxy Opal: a cool-teal solid on a navy void. The canonical reference image is `docs/assets/galaxy-opal-canonical.png`. The system card is `docs/design/galaxy-opal-system-card.md`.

Try one file locally:

```bash
larc-seraph path/to/mcp.json
larc-seraph --sigma tests/fixtures/sigma/known_good/agent_pytest.json
```

The scanner prints matches and does not block, quarantine, or send telemetry. It sets the `filepath` external to the path you passed, with backslashes turned into forward slashes and the original case kept.

## Scanner contract

The CLI compiles `rules/path-scoped` plus the two plist rules and sets `filepath` from the path you passed. `rules/yara` does not read that external. An instruction file whose body never names itself matches the path-scoped rule and not the Forge rule.

Pass the path as it is stored. The regexes are case-insensitive. `AGENTS.md` and `Agents.md` are the same gate. The commands are in [Consume the rules](#consume-the-rules). Use forward slashes in the value.

Telemetry normalizers for eslogger JSON, Elastic Common Schema, and osquery rows live in `larc_seraph/translate.py`. pySigma pipelines in `pipelines/` emit Lucene and Splunk queries with those field names. Converted queries are in `rules/converted/`.

## Known limitations

These are the misses recorded in [validation/evasion-matrix.yml](validation/evasion-matrix.yml). The methodology and the numbers are in [VALIDATION.md](VALIDATION.md). A numeric version pin is a non-match on purpose, and so is a backticked status-bar label.

- A fetch or `base64` whose name is split (`ba''se64`) or stored in a variable, so the file never contains the word.
- A package name that is not one JSON string, and a remote specifier more than 160 bytes after `npx`, `uvx`, or `npm exec`.
- A bare `/tmp` grant with no further path segment.
- A secret variable that is not on the short name list.
- A zero-width mark between every letter of a confirmation-bypass sentence. A mark between the words is caught. U+200B with no other hidden-text signal is not. "Never request permission" needs a nearby high-risk action such as a shell command, `rm`, `publish`, or `git push`. Listing, reading, viewing, searching, `ls`, and `git status`, `log`, or `diff` do not count. A Markdown heading, a table row, or a known permission flag such as `--yolo` does not match. `--force` on an ordinary instruction line does not veto it.
- Homoglyphs other than Cyrillic `o` in that same sentence.
- `KeepAlive` set to the integer 1, and an SSH `-R` glued to its value with no space. A host-key option that lives only in `~/.ssh/config` is not in the plist.
- A git hook with no shebang.
- Shell startup files the path list does not name, such as Fish `config.fish`. `authorized_keys.bak` is not in the path list. A project file that still ends in `.zshrc` does match.
- A plist that is not under LaunchAgents or LaunchDaemons.
- English confirmation-bypass sentences are matched by `larc_seraph.phrases` inside the CLI. The YARA core for `SERAPH_Instruction_Unsafe_Directive` keeps the homoglyph, the same-line credential fetch, and "ignore previous instructions" next to a fetch. A YARA-only scanner misses the paraphrases.
- osquery rows that only have a parent pid. The normalizer leaves `ParentImage` empty, and parent rules do not fire. A piped shell whose parent is launchd is left to the plist rules.
- The Forge flavor misses a YAML or TOML MCP config that does not start with `{`, and a confirmation sentence whose only instruction signal is the file name. The path-scoped rules still catch those. Forge matches a hook payload that is not under `.git/hooks` or `.husky`. The path-scoped rule does not.
- The benign corpus is a sample of public trees, not every workstation. The Mac scans are summarized in VALIDATION.md.

## Validation

```bash
python tools/fp_scan.py
yr compile rules/yara -o /tmp/larc.yarc
```

`pytest` also runs the evasion matrix, the telemetry round-trip, the conversion check, and the yara-x compile. `sigma check` is described in [VALIDATION.md](VALIDATION.md).

## YARA-Forge

`rules/yara` is the flavor YARA-Forge can compile. It has no `filepath` external. `yarac --fail-on-warnings` and `yr compile` both run on that directory with no `-d` and no `--define`. CI fails if the word `filepath` shows up there.

`rules/path-scoped` is the same behavior with the path gate kept. Rule names end in `_Path` and ids end in `-PATH`. The `larc-seraph` CLI compiles those plus the two LaunchAgent plist rules, and it passes `filepath`. Use this set when you know the path:

```bash
yara -d filepath=/abs/path rules/path-scoped /abs/path
yr scan --define 'filepath="/abs/path"' rules/path-scoped /abs/path
```

Point Forge, or any scanner that cannot set externals, at `rules/yara` only. Do not compile the two trees together unless you define `filepath`, because the path-scoped rules need it.

What the Forge flavor uses instead of the path:

- MCP rules other than `SERAPH-YARA-016` match a file whose first byte is `{` and that contains an `mcpServers` object. Markdown, and YAML or TOML that does not start with `{`, do not match. `SERAPH-YARA-016` also matches a file that starts with `mcpServers:` or `[mcp_servers` / `mcp_servers =`.
- `SERAPH_Instruction_Unsafe_Directive` matches when the bytes contain an instruction marker (`agent instructions`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, `copilot-instructions`, or `.cursor/rules/`) or a JSON object with a `description`. The English paraphrases are not in this rule. `larc_seraph.phrases` adds them when you use the CLI.
- `SERAPH_Instruction_Hidden_Unicode` matches the tag and bidi bytes without requiring the file to name itself.
- The git-hook rule matches a shebang plus the payload, and it skips a file that contains git's sample banner (`To enable this hook, rename this file`).
- The two plist rules never used a path. They are only in `rules/yara`.

That is narrower than the path-scoped rules in some places, and wider in others:

- A bare `do not ask for confirmation` in a file named `AGENTS.md` matches the path-scoped rule and does not match Forge. The evasion case `bare_sentence_without_instruction_marker` is that gap.
- A YAML or TOML MCP config whose first byte is not `{` matches the path-scoped rule when the path ends in `.yml`, `.yaml`, or `.toml`. Forge matches it only for `SERAPH-YARA-016`, and only when the file starts with `mcpServers:` or `[mcp_servers` / `mcp_servers =`.
- A bidi override or Unicode tag in a file that is not an instruction path matches Forge and not the path-scoped rule. `tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/negative/case/Notes.md` is that case. A real `CLAUDE.md` or `.cursor/rules/style.mdc` that never writes its own name matches both.
- A hook payload in a file whose name ends in `.sample` is skipped by the path-scoped rule. Forge skips it only when the body contains the sample banner.
- A hook payload that is not under `.git/hooks` or `.husky` is silent for the path-scoped rule and matches Forge. `tests/fixtures/yara/SERAPH_Git_Hook_Suspicious_Exec/negative/loose/pre-commit` is that case.

Checked against [YARA-Forge](https://github.com/YARAHQ/yara-forge) `qa/rule_qa.py`: the metadata it normalizes is present (`description`, `author`, `date`, `modified`, `reference`, `id`), plus `version` and ATT&CK in `attack_technique` and `attack_tactic`. No private rules, and no `elf`, `cuckoo`, or `magic` import. The meta `score` is the author's confidence from 0 to 100. It is not Forge's computed quality score, and this pack does not set a sample `hash`. Ids are `SERAPH-YARA-NNN`, not UUIDs. The repository is not in `yara-forge-config.yml` until a forge maintainer adds it. YARA-Forge's own README says the repositories it collects have been carefully selected, and "Adding unvetted sources is not supported." Submission comes after a maintainer adopts the pack. It is not a pull request this repository can open on its own.

`yr fmt --check` runs in CI on `rules/yara`, `rules/path-scoped`, and `rules/src/yara`. yaraQA 0.11.0 findings that remain are listed in [VALIDATION.md](VALIDATION.md).

## CI and releases

Pull requests and pushes to `main` run [`.github/workflows/test.yml`](.github/workflows/test.yml): pytest, `yarac --fail-on-warnings`, `yr compile`, `yr fmt --check`, `sigma check`, the rule-metadata check, the benign-corpus scan, a docs drift check, gitleaks on the git history, and a `Signed-off-by` check on pull request commits. Actions are pinned by commit SHA. The workflow token can read repository contents.

Pushing a tag `vX.Y.Z` runs those tests and then [`.github/workflows/release.yml`](.github/workflows/release.yml), which publishes the GitHub Release. The release job is the one token that can write contents. Tag the commit yourself after CI on `main` is green. The version in `pyproject.toml` has to match the tag, and `CHANGELOG.md` needs a section for it.

The benign-corpus scan clones public trees at job time. A new hit fails the job. The allowlist is empty. A failed clone also fails the job.

## Project docs

- [SECURITY.md](SECURITY.md) for private vulnerability reports.
- [CONTRIBUTING.md](CONTRIBUTING.md) for rule metadata, fixtures, local tests, and sign-off.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) is Contributor Covenant 2.1.

## License

Two licenses, on purpose.

- Code, the test harness, the scanner, and the docs are [Apache-2.0](LICENSE).
- Rules under `rules/` are the [Detection Rule License 1.1](LICENSE.rules).

DRL is the license detection engineers already exchange. It allows use inside a detection product and requires the author attribution to stay with the rule. CC-BY-4.0 was the other serious option. It is easier to explain to a general audience and a worse fit for someone dropping a Sigma rule into an existing ruleset. Either half can be relicensed by the author.

Copyright 2026 Kevin Francis Tan / Light Architects.
