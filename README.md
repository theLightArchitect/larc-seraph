![SERAPH — detection content for agent tooling on the workstation](docs/assets/banner.svg)

# SERAPH

Defensive detection content for AI-agent tooling on developer workstations, written by Kevin Francis Tan / Light Architects ([lightarchitects.ai](https://lightarchitects.ai)).

YARA rules for the files an agent trusts. Sigma rules for the macOS events those files become. Synthetic fixtures and a pytest harness so a match means what the catalog says it means.

The docs site is [docs/index.html](docs/index.html). The threat model and field contract are [docs/content/threat-model.md](docs/content/threat-model.md).

## What this is

Fifteen experimental rules:

| ID | Engine | What it watches |
| --- | --- | --- |
| `SERAPH_MCP_Launch_From_Temp` | YARA | MCP command launched from a temp or cache path |
| `SERAPH_MCP_Curl_Pipe_Shell` | YARA | MCP config pipes a fetch into a shell |
| `SERAPH_MCP_Encoded_Exec` | YARA | MCP config decodes into a shell or eval |
| `SERAPH_MCP_Remote_Npx` | YARA | npx or uvx from a URL, `github:` specifier, or `@latest` |
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

Each rule carries author, date (2026-11-13), ATT&CK mapping, severity, scope, and a false-positive note. Status is experimental.

## What this is not

This is not an EDR, a blocker, or a claim of coverage. It is not offensive tooling. Fixtures under `tests/fixtures/` are synthetic and inert, labelled `synthetic-benign`, and use `example.invalid` where a host appears. Do not execute them. A green test run proves the fixtures and the rule metadata. It does not prove a fleet false-positive rate.

Sigma rules assume a normalized macOS field contract (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`). They do not match raw Apple unified logs until a translator maps Endpoint Security events onto those names. The threat model states that limit in full.

The stock `npx -y @scope/package` quickstart, with no URL and no `@latest`, is a known-good. Flagging it would flag the published way to start several official MCP servers.

## Run the tests

Python 3.11 or newer.

```bash
pip install -e ".[test]"
pytest
```

`pytest` compiles the YARA pack, checks every positive and negative fixture, evaluates the Sigma rules through pySigma's condition tree, and runs `sigma check --fail-on-issues`. The ATT&CK tag check downloads MITRE's published STIX once and caches it.

Regenerate the HTML site after a rule or write-up change:

```bash
python -m seraph.docsgen
python -m seraph.docsgen --check
```

Open `docs/index.html` in a browser. It is a static site. No server is required. The visual language is Galaxy Opal: a cool-teal solid on a navy void. The canonical reference image is `docs/assets/galaxy-opal-canonical.png`. The system card is `docs/design/galaxy-opal-system-card.md`.

Try one file locally:

```bash
seraph-scan path/to/mcp.json
seraph-scan --sigma tests/fixtures/sigma/known_good/agent_pytest.json
```

The scanner prints matches and does not block, quarantine, or send telemetry.

## License

Two licenses, on purpose.

- Code, the test harness, the scanner, and the docs are [Apache-2.0](LICENSE).
- Rules under `rules/` are the [Detection Rule License 1.1](LICENSE.rules).

DRL is the license detection engineers already exchange. It allows use inside a detection product and requires the author attribution to stay with the rule. CC-BY-4.0 was the other serious option. It is easier to explain to a general audience and a worse fit for someone dropping a Sigma rule into an existing ruleset. Either half can be relicensed by the author.

Copyright 2026 Kevin Francis Tan / Light Architects.
