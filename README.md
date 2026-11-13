![larc-seraph — detection content for agent tooling on the workstation](docs/assets/banner.svg)

# larc-seraph

Defensive detection content for AI-agent tooling on developer workstations, written by Kevin Francis Tan / Light Architects ([lightarchitects.ai](https://lightarchitects.ai)).

Rule IDs stay in the `SERAPH-YARA` and `SERAPH-SIGMA` series. The pack name is larc-seraph.

YARA rules for the files an agent trusts. Sigma rules for the macOS events those files become. Synthetic fixtures and a pytest harness so a match means what the catalog says it means.

The docs site is [docs/index.html](docs/index.html). The threat model and field contract are [docs/content/threat-model.md](docs/content/threat-model.md).

## What this is

Seventeen experimental rules:

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

Each rule carries author, date (2026-11-13), ATT&CK mapping, severity, scope, and a false-positive note. Status is experimental.

## What this is not

This is not an EDR, a blocker, or a claim of coverage. It is not offensive tooling. Fixtures under `tests/fixtures/` are synthetic and inert, labelled `synthetic-benign`, and use `example.invalid` where a host appears. Do not execute them. A green test run proves the fixtures and the rule metadata. It does not prove a fleet false-positive rate.

Sigma rules assume a normalized macOS field contract (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`). They do not match raw Apple unified logs until a translator maps Endpoint Security events onto those names. The threat model states that limit in full.

`SERAPH-YARA-016` flags an unpinned registry package inside a JSON, TOML, or YAML MCP config. `@modelcontextprotocol`, `@anthropic`, and `@github` are allowlisted. A numeric version pin is not a match. A Markdown README that only quotes the config is not a match.

## Run the tests

Python 3.11 or newer.

```bash
pip install -e ".[test]"
pytest
```

`pytest` compiles the YARA pack, checks every positive and negative fixture, evaluates the Sigma rules through pySigma's condition tree, and runs `sigma check --fail-on-issues`. The ATT&CK tag check downloads MITRE's published STIX once and caches it.

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

Rules that care about a path read the external string `filepath`. An empty value means the scanner did not say where the bytes came from. Instruction rules and the git-hook rule then do not match. MCP rules still match a file whose first byte is `{`.

Pass the path as it is stored. The regexes are case-insensitive. `AGENTS.md` and `Agents.md` are the same gate.

```bash
yara -d filepath=/abs/path rules/yara /abs/path
yr scan --define 'filepath="/abs/path"' rules/yara /abs/path
```

```python
rules.match(path, externals={"filepath": path})
```

`larc-seraph path/to/AGENTS.md` does this itself. Use forward slashes in the value. Quote the YARA-X define so the shell does not eat the quotes around the path.

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
- An MCP file that contains both a pinned package and an unpinned one can suppress `SERAPH-YARA-016`, because a numeric version anywhere in the file clears it.
- osquery rows that only have a parent pid. The normalizer leaves `ParentImage` empty, and parent rules do not fire. A piped shell whose parent is launchd is left to the plist rules.
- The benign corpus is a sample of public trees, not every workstation. The Mac scans are summarized in VALIDATION.md.

## Validation

```bash
python tools/fp_scan.py
yr compile rules/yara -o /tmp/larc.yarc
```

`pytest` also runs the evasion matrix, the telemetry round-trip, the conversion check, and the yara-x compile. `sigma check` is described in [VALIDATION.md](VALIDATION.md).

## License

Two licenses, on purpose.

- Code, the test harness, the scanner, and the docs are [Apache-2.0](LICENSE).
- Rules under `rules/` are the [Detection Rule License 1.1](LICENSE.rules).

DRL is the license detection engineers already exchange. It allows use inside a detection product and requires the author attribution to stay with the rule. CC-BY-4.0 was the other serious option. It is easier to explain to a general audience and a worse fit for someone dropping a Sigma rule into an existing ruleset. Either half can be relicensed by the author.

Copyright 2026 Kevin Francis Tan / Light Architects.
