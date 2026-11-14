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

Seventeen experimental rules:

| ID | Engine | What it watches |
| --- | --- | --- |
| `SUSP_SERAPH_MCP_Launch_From_Temp` | YARA | MCP command launched from a temp or cache path |
| `SUSP_SERAPH_MCP_Curl_Pipe_Shell` | YARA | MCP config pipes a fetch into a shell |
| `SUSP_SERAPH_MCP_Encoded_Exec` | YARA | MCP config decodes into a shell or eval |
| `SUSP_SERAPH_MCP_Remote_Npx` | YARA | npx or uvx from a URL, `github:` specifier, or `@latest` |
| `SUSP_SERAPH_MCP_Unpinned_Package` | YARA | npx or uvx package with no numeric version |
| `SUSP_SERAPH_MCP_Secret_Exfil` | YARA | A token variable interpolated into a URL or a fetch |
| `SUSP_SERAPH_Instruction_Hidden_Unicode` | YARA | Unicode tags or bidi overrides in instruction files |
| `SUSP_SERAPH_Instruction_Unsafe_Directive` | YARA | Confirmation bypass, or a credential path next to a sink |
| `SUSP_SERAPH_LaunchPlist_Writable_Interpreter` | YARA | RunAtLoad, KeepAlive, a shell, and a user-writable path |
| `SUSP_SERAPH_LaunchPlist_SSH_Reverse_Tunnel` | YARA | Reverse SSH in a plist with host-key checking disabled |
| `SUSP_SERAPH_Git_Hook_Suspicious_Exec` | YARA | Hook decodes into a shell, or posts a credential path |
| `SERAPH_MacOS_Agent_Writes_Authorized_Keys` | Sigma | Agent host writes `authorized_keys` |
| `SERAPH_MacOS_Agent_Modifies_Shell_RC` | Sigma | Agent host writes a user shell startup file |
| `SERAPH_MacOS_Interpreter_Drops_Launch_Plist` | Sigma | Interpreter writes a LaunchAgent or LaunchDaemon plist |
| `SERAPH_MacOS_SSH_Reverse_Lax_HostKey` | Sigma | ssh reverse forward with host-key checking disabled |
| `SERAPH_MacOS_Agent_Piped_Shell` | Sigma | Agent parent spawns a fetch or decode handed to a shell |
| `SERAPH_MacOS_Node_Starts_AI_CLI_Skip_Permissions` | Sigma | A JavaScript runtime or package manager starts an AI CLI with a skip-permission flag |

Each rule carries author, date (2026-11-13), ATT&CK mapping, severity, scope, and a false-positive note. Status is experimental.

## What this is not

This is not an EDR, a blocker, or a claim of coverage. It is not offensive tooling. Fixtures under `tests/fixtures/` are synthetic and inert, labelled `synthetic-benign`, and use `example.invalid` where a host appears. Do not execute them. A green test run proves the fixtures and the rule metadata. It does not prove a fleet false-positive rate.

Sigma rules assume a normalized macOS field contract (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`). They do not match raw Apple unified logs until a translator maps Endpoint Security events onto those names. The threat model states that limit in full.

`SERAPH-YARA-016` flags an unpinned registry package inside a JSON, TOML, or YAML MCP config. `@modelcontextprotocol`, `@anthropic-ai`, and `@github` are allowlisted on that package entry. A numeric version on the package token is not a match, and a pin or an allowlisted package elsewhere in the file does not clear a second unpinned package. A Markdown README that only quotes the config is not a match.

`SERAPH-SIGMA-016` and `SERAPH-SIGMA-017` are retired numbers. Both belonged to the terminal piped-shell rule, which is removed. A command typed or pasted into Terminal is parsed by the interactive shell: each side of the pipe is its own process, and no process's arguments contain the pipe, so a single-event rule cannot see it. `SERAPH-SIGMA-018` is the Nx s1ngularity CLI rule. The metadata check rejects a repeated three-digit number across the two families. YARA rule names start with the Neo23x0 category `SUSP_` (suspicious configuration or behavior, not a malware family), then `SERAPH_`, then the subject: `SUSP_SERAPH_MCP_Curl_Pipe_Shell`. The name before the prefix is kept in an `old_rule_name` meta field, so a search for `SERAPH_MCP_Curl_Pipe_Shell` still finds the rule. Sigma rule names stay `SERAPH_MacOS_*`; the category prefix is a YARA naming convention.

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
# Forge / no externals. libyara takes rule files, yara-x takes the directory.
yara rules/yara/*.yar /abs/path
yr scan rules/yara /abs/path

# Path-scoped, when you know the path. The two plist rules never read a path
# and live only in rules/yara, so name them too.
yara -d filepath=/abs/path rules/path-scoped/*.yar rules/yara/launchplist_*.yar /abs/path
yr scan --define 'filepath="/abs/path"' rules/path-scoped rules/yara/launchplist_ssh_reverse_tunnel.yar rules/yara/launchplist_writable_interpreter.yar /abs/path
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

A green test run, and a detection that works on the committed fixtures, is not coverage. This pack matches bytes in files and fields in events. It does not parse JSON, run a shell, follow a symlink, open a second file, or see a process tree. Anything an attacker can write without one of those literals, or in a place a rule does not read, passes. A rule that matched it would also match ordinary files.

The misses are recorded in [validation/evasion-matrix.yml](validation/evasion-matrix.yml), 185 cases, each asserted by pytest. 60 of them are a miss in at least one flavor or engine, and they are grouped below by the reason static matching cannot close them without ordinary files matching too. An id is `rule number/case name`; `006-e10` is a review-harness fixture that is not a matrix body. The methodology and the numbers are in [VALIDATION.md](VALIDATION.md). A numeric version pin is a non-match on purpose, and so is a backticked status-bar label.

1. The file never holds the literal the rule needs: the tool or variable name is split, built up, or read from elsewhere. `002/curl_hidden_in_variable`, `003/split_base64_token`, `016/package_built_by_concatenation`, `005/token_read_indirectly`
2. Needs decoding or normalization a byte signature cannot do: letters written as entities, or invisible characters inside a word. `008/xml_entities_in_letters`, `007/zero_width_between_every_letter`, `007/soft_hyphen_inside_a_word`
3. Whether a string is a launched program or data depends on a flag, a distance, or a later command, and a wider window matches README links and ordinary scripts. `001/tmp_without_trailing_segment`, `001/temp_script_after_value_flag`, `004/shorthand_after_value_flag`, `004/url_split_from_npx_by_distance`, `003/decode_chmod_then_interpreter_on_file`, `010/download_to_null_then_run`, `015/separator_inside_a_quoted_value`, `010/download_named_as_data_then_run`
4. Deliberate non-match: a numeric pin, a tag another rule owns, or a first-party installer line on the exact-URL list. `016/version_pin`, `016/security_placeholder_pin`, `016/dist_tag_next`, `007/vendor_installer_url_in_quotes`, `007/vendor_installer_no_space_before_pipe`
5. Documentation shapes are vetoed so that docs stay silent: a Markdown heading, a table row, a status-bar label, or a flag in a list. `007/force_flag_table_row`, `007/yolo_heading`, `007/status_label_bypass_permissions_on`, `007/heading_after_many_flags`, `007/directive_in_a_table_row`, `007/directive_as_a_heading`
6. The sentence needs a high-risk action in the same sentence, and a read-only or low-risk instruction matches ordinary prose. `007/listing_files_is_read_only`, `007/read_only_word_on_the_line`, `007/never_request_permission_without_action`, `007/push_in_another_sentence`
7. A prohibition anywhere on the line vetoes it, so a line that forbids one thing and demands another is missed. `007/never_proceed_without_confirmation`, `007/negated_clause_on_the_line`
8. Outside the byte model: one language, and a file larger than the 5 MB scan cap (the second is a review-harness case, not a matrix body). `007/other_language`, `006-e10` (over 5 MB, harness only)
9. The evidence is in another file, another process, or another rule's scope, and one file or one event does not hold it. `010/payload_in_a_second_file`, `009/hostkey_in_ssh_config_not_argv`, `009/options_in_a_config_file`, `014/options_in_a_config_file`, `015/launchd_parent`, `011/agent_is_the_grandparent`, `012/agent_is_the_grandparent`, `011/symlink_target_elsewhere`
10. The file fails a path, name, directory, or shebang gate, and dropping the gate matches every file of that shape. `011/authorized_keys_backup_name`, `012/git_config`, `013/plist_outside_launchd_dirs`, `006/contributing_guide_is_not_an_instruction_path`, `010/sample_hook_name`, `010/python_hook_without_shebang_token`
11. The Forge flavor has no path, and a gate that needs one would match source files, so Forge differs from the path-scoped rule. `001/jsonc_opens_with_a_comment`, `006/eight_control_bytes_first`, `007/bare_sentence_without_instruction_marker`
12. Matching it flags ordinary developer work: login jobs, installers, routine agent edits, or a shell started by a person. `008/run_at_load_only`, `008/start_interval_instead_of_keepalive`, `008/writable_binary_without_interpreter`, `008/script_under_opt`, `011/ssh_config_write`, `013/moved_into_place`, `013/copied_into_place`, `015/node_parent_shell`, `018/zsh_parent_skip`, `006/zero_width_space_only`

The UTF-16 tag-character case (`006-e9`, review-harness only) is closed. The Unicode-tag rule reads tag characters in UTF-16 text, little- or big-endian, when the file starts with a byte order mark. UTF-16 text without a byte order mark is not read, and bidi controls, variation selectors, and zero-width runs in UTF-16 are not read: the byte order mark is what separates 16-bit text from binary.

Other limits that are not recorded as an evasion case:

- A zero-width mark inside a word of a confirmation-bypass sentence is not caught. A mark between the words counts as a gap and is caught, and so is a no-break space or an em space. A run of eight or more zero-width characters is a match; a lone U+200B is not. "Never request permission" needs a high-risk action on the same line, such as a shell command, `rm`, `publish`, or `git push`. Listing, reading, viewing, searching, `ls`, and `git status`, `log`, or `diff` do not count. A Markdown heading, a table row, or a known permission flag such as `--yolo` does not match. `--force` on an ordinary instruction line does not veto it.
- A sentence may wrap once between its own words and still match. The high-risk word that some sentences need has to be on the same line as the phrase. A phrase that starts more than 1000 bytes into its line is a match outright, with no veto, because `yara-python` 4.5.4 cannot match a longer span and padding a line that far is not ordinary writing.
- A prohibition. "Never bypass permissions", "do not run `curl ... | sh`", and "never run with `--dangerously-skip-permissions`" do not match. "Never launch claude without `--dangerously-skip-permissions`" does, and so does "whenever". A prohibition anywhere on a line vetoes that line, so a line that forbids one thing and demands another is missed.
- Homoglyphs other than Cyrillic `o` in a confirmation-bypass sentence are not matched.
- The plist rules read a binary plist by its key and interpreter strings, not by its boolean values, and UTF-16 text only as little-endian.
- English confirmation-bypass sentences are generated into `SUSP_SERAPH_Instruction_Unsafe_Directive` from `larc_seraph.phrases`. The CLI's phrase module compiles the same byte patterns the rule holds and follows the rule's condition step by step, and a test compares the two on every fixture and every evasion-matrix body. The CLI used to match four things YARA cannot express: a zero-width mark inside a word, a high-risk word on the line above or below, a pipe followed by a newline, and a file over 5 MB. It no longer does.
- More than 256 occurrences of one bypass phrase, or more than 256 pipes into a shell, is a match by count. Tag characters and scoped packages are counted with no bound.
- In an instruction file, a fetch piped into `python3`, `node`, or another interpreter that is not a shell is not a sink. The MCP fetch and decode rules read a bare interpreter after the pipe; the instruction rule does not. A shell name followed by `|` (a Markdown table cell) or by more word characters is not a sink.
- A pipe into a shell in an instruction file matches unless the whole command is one listed first-party installer line. It has to start a line (or follow a shell prompt or a backtick), use only options from a short closed list, name one exact URL from `INSTALLER_URLS`, and pipe into `sh` or `bash` with nothing after it but `-s` arguments. A second URL, a header, a path or query after the URL, any other option, an environment prefix, or a script name after the shell keeps the match. No third-party repository is on the list, so a vendor install line that is not listed matches too. That is most of the noise on a developer Mac (see the re-scan in VALIDATION.md).
- The Forge instruction rules skip a file whose first kilobyte holds eight or more control bytes. A file padded that way is not scanned by Forge. The path-scoped rules have no such check.
- A vendor host only counts when the URL's authority ends there. An IP address or a bare host name is a URL like any other.
- An AWS secret has no vendor host. `AWS_SECRET_ACCESS_KEY` beside a fetch and any URL matches.
- JSON string escapes are tested only for the temp-path rule (`SERAPH-YARA-001`) and the fetch-pipe rule (`SERAPH-YARA-002`), which accept `\u002f`, `\/` and escaped letters. The other MCP rules read bytes and do not parse JSON, and no matrix case covers an escape for them, so treat an escape there as unverified.
- `SERAPH-SIGMA-018` reads `claude-code/cli.js` in the command line for an npm-installed Claude. A `/bin/sh` parent matches, because `child_process.exec` puts a shell between node and the CLI, so a shell script that starts the CLI with the flag matches too. The `q chat -a` short form comes from a pull request's text and is not verified on a current build.
- osquery rows that only have a parent pid. The normalizer leaves `ParentImage` empty, and parent rules do not fire.
- The Forge flavor misses a JSONC MCP config that opens with a comment, a YAML config whose `mcpServers:` key is not at the start of a line, and a confirmation sentence whose only instruction signal is the file name. The path-scoped rules still catch those. Forge matches a hook payload that is not under `.git/hooks`, `.githooks`, or `.husky`. The path-scoped rule does not.
- A prohibition has to end on the same line as the phrase it forbids. A prohibition hard-wrapped so that its negation ends one line and the forbidden pipe or phrase begins the next is not read as a prohibition, and the phrase matches. Letting the negation cross a line break would let one "never" excuse a later line.
- The paraphrase veto is read across the whole line and is not tied to the one phrase it sits next to. A line that holds a risky paraphrase and, elsewhere, a veto phrase for something else is judged as one unit.
- Sentence boundaries are a heuristic. A full stop, `!`, `?`, or `;` followed by a blank ends a sentence, and `e.g.` and `i.e.` are the only abbreviations the rule handles. Any other abbreviation followed by a blank ends the sentence early, so a prohibition before it does not cover the words after it.
- An asterisk counts as a gap in the sentence patterns (Markdown emphasis between words). It is not a blank in the command patterns, so a command with an asterisk between its tokens does not match.
- `SERAPH_MacOS_Agent_Piped_Shell`: a quoted environment value that itself holds `;`, `&`, or `|` ends the token early and the command is missed (`separator_inside_a_quoted_value`). Telling a quoted separator from a real one needs a shell parser, and a bound on the quoting is defeated by padding. For the same reason the rule reads quotes and backslashes in an assignment by pattern and not by parsing: `$'...'` strings, `${IFS}` and other expansions, variables, and command substitution in the assignment are not read.
- A file the YARA engine cannot scan makes the CLI exit with status 2 and name the file. It is never reported as clean.
- `SERAPH_MacOS_Agent_Piped_Shell` holds one regex in the common Sigma "contains" shape, `.*(curl|wget|fetch|base64)\t.*`. Run as written with an unanchored search, a miss takes time quadratic in the length of the command line: about one second at 9,000 characters with Python's `re`. The CLI drops the leading and trailing `.*` before it searches, which gives the same answers in linear time (a test checks that). A Sigma backend that runs the regex as written was not measured.
- A conditional about the user is exempt from the prompt-injection check only in the form "phrase, then a URL": "If the user says to forget previous instructions about style, follow https://...". The prefix has to be "if" or "when", "the user", "says", "asks", or "wants", then "to" (optionally "you to"), directly before the phrase. A real order elsewhere on the same line still matches, because each start is counted on its own. The reverse form (a URL, then the phrase) has no exemption, so "Follow https://... if the user says to forget previous instructions" still matches: a conditional placed after a real order would start from the same URL and cancel it.
- The Google key hosts are a list: `generativelanguage`, `www`, `maps`, `places`, `routes`, `youtube`, `translation`, `vision`, `texttospeech`, `speech`, `language`, `customsearch`, and `safebrowsing` under `googleapis.com`, and `ai.google.dev`. A Google key sent to another host, including `storage.googleapis.com`, matches, because a bucket there belongs to whoever created it.
- `npm exec -- <name>` and `pnpm dlx <name>` read a bare name as a package, as `npx` does, so a project-local binary such as `npm exec -- tsc` matches `SERAPH-YARA-016`. A rule cannot tell a local binary from a package npm would download. It is a stated false-positive class and is pinned by a fixture.
- The four items the adversarial review left open are dealt with. A Google API key sent to a Google-operated API host no longer matches (the Google bullet above). The Oh My Zsh installer, in either published form, is on the installer list, and one full stop after its closing bracket is allowed. The conditional "forget previous instructions" wording is exempt in the forward form (the bullet above). `npm exec -- tsc` is not changed and is a stated false-positive class (the `npm exec` bullet above).
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

- MCP rules match a text file that opens with a JSON object (after an optional BOM or blank space, within the first 4 KB), has a top-level `mcpServers:` key, or has an `mcp_servers` table or assignment at the start of a line. The file also has to contain a server map: `mcpServers`, Codex `[mcp_servers.<name>]`, Zed `context_servers`, or a VS Code `servers` object beside a `command` key. Markdown and a JSONC file that opens with a comment do not match. `SERAPH-YARA-016` accepts the YAML and TOML forms only at the start of the file.
- `SUSP_SERAPH_Instruction_Unsafe_Directive` matches when the bytes contain an instruction marker (`agent instructions`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, `copilot-instructions`, or `.cursor/rules/`) or a JSON object with a `description`, and the sentence list generated from `larc_seraph.phrases`.
- `SUSP_SERAPH_Instruction_Hidden_Unicode` matches the tag and bidi bytes without requiring the file to name itself. Every tag character counts, however many flag emoji come first. Only the England, Scotland, and Wales flag sequences are exempt.
- The git-hook rule matches a shebang plus the payload, and it skips a file that contains git's sample banner (`To enable this hook, rename this file`).
- The two plist rules never used a path. They are only in `rules/yara`.

That is narrower than the path-scoped rules in some places, and wider in others:

- A bare `do not ask for confirmation` in a file named `AGENTS.md` matches the path-scoped rule and does not match Forge. The evasion case `bare_sentence_without_instruction_marker` is that gap.
- A JSONC MCP config that opens with a comment matches the path-scoped rule by its extension. Forge does not match it, because source files open with a comment too.
- A bidi override or Unicode tag in a file that is not an instruction path matches Forge and not the path-scoped rule. `tests/fixtures/yara/SUSP_SERAPH_Instruction_Hidden_Unicode/negative/case/Notes.md` is that case. A real `CLAUDE.md` or `.cursor/rules/style.mdc` that never writes its own name matches both.
- A hook payload in a file whose name ends in `.sample` is skipped by the path-scoped rule. Forge skips it only when the body contains the sample banner.
- A hook payload that is not under `.git/hooks`, `.githooks`, or `.husky` is silent for the path-scoped rule and matches Forge. `tests/fixtures/yara/SUSP_SERAPH_Git_Hook_Suspicious_Exec/negative/loose/pre-commit` is that case.

Checked against [YARA-Forge](https://github.com/YARAHQ/yara-forge) `qa/rule_qa.py`: the metadata it normalizes is present (`description`, `author`, `date`, `modified`, `reference`, `id`), plus `version` and ATT&CK in `attack_technique` and `attack_tactic`. No private rules, and no `elf`, `cuckoo`, or `magic` import. The meta `score` is an integer, the author's confidence from 0 to 100, and extra URLs repeat the `reference` key. The Forge copies of the git-hook rule and the two instruction rules score 45 to 50, lower than their path-scoped twins, because with no path they also match installer scripts, right-to-left text, and source code that names an instruction file. Their descriptions say so. It is not Forge's computed quality score, and this pack does not set a sample `hash`. Ids are `SERAPH-YARA-NNN`, not UUIDs. The repository is not in `yara-forge-config.yml` until a forge maintainer adds it. YARA-Forge's own README says the repositories it collects have been carefully selected, and "Adding unvetted sources is not supported." Submission comes after a maintainer adopts the pack. It is not a pull request this repository can open on its own.

`yr fmt --check` runs in CI on `rules/yara`, `rules/path-scoped`, and `rules/src/yara`. The yaraQA 0.11.0 findings in [VALIDATION.md](VALIDATION.md) were recorded before the review fixes and have not been re-run, _audit pending_.

## CI and releases

Pull requests and pushes to `main` run [`.github/workflows/test.yml`](.github/workflows/test.yml): pytest, `yarac --fail-on-warnings`, `yr compile`, `yr fmt --check`, `sigma check`, the rule-metadata check, the benign-corpus scan, a docs drift check, gitleaks on the git history, and a `Signed-off-by` check on pull request commits. Actions are pinned by commit SHA. The workflow token can read repository contents.

Pushing a tag `vX.Y.Z` runs those tests and then [`.github/workflows/release.yml`](.github/workflows/release.yml), which publishes the GitHub Release. The release job is the one token that can write contents. Tag the commit yourself after CI on `main` is green. The version in `pyproject.toml` has to match the tag, and `CHANGELOG.md` needs a section for it.

The benign-corpus scan clones public trees at job time. A new hit fails the job. `validation/fp-allowlist.txt` holds one accepted hit. A failed clone also fails the job.

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
