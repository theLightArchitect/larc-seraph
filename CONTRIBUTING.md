# Contributing to larc-seraph

Detection content for AI-agent configs, instruction files, MCP servers, git hooks, and macOS LaunchAgents. Issues and pull requests are welcome. Security reports go through [SECURITY.md](SECURITY.md), not through a public issue.

The code of conduct is [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Rule style

One rule per file. YARA rule names stay in the `SERAPH_` series. Stable ids stay in `SERAPH-YARA-NNN` and `SERAPH-SIGMA-NNN`. The file header states the copyright, the Detection Rule License 1.1, and that the rule is defensive.

Rules describe suspicious shapes. They are not exploits and not payloads. Fixtures are synthetic and inert. Hosts in fixtures are `example.invalid`. A fixture file contains the label `synthetic-benign`.

YARA ships as two flavors generated from `rules/src/yara` by `python tools/build_rule_flavors.py`. Edit the source, regenerate, and commit both outputs. `pytest` fails if they drift.

- `rules/yara` is the Forge flavor. Canonical rule names and `SERAPH-YARA-NNN` ids. It must compile with no externals. Do not write `filepath` in that tree.
- `rules/path-scoped` is the path-scoped flavor. Names end in `_Path`, ids end in `-PATH`, and the rules read `filepath`. The CLI uses this set plus the plist rules.

Pass `filepath` as the path is stored, with forward slashes, and keep the original case. The path regexes are case-insensitive. The Forge flavor cannot see that string. MCP rules there require a leading `{`, except `SERAPH-YARA-016`, which also accepts a file that starts with `mcpServers:` or `[mcp_servers`. `SERAPH_Instruction_Unsafe_Directive` on Forge requires an in-file marker such as `agent instructions` or `AGENTS.md`. `SERAPH_Instruction_Hidden_Unicode` on Forge does not: the tag and bidi bytes are the signal, because a real `CLAUDE.md` or `.cursor/rules` file often does not name itself. The git-hook rule there skips git's sample banner instead of a `.sample` filename.

English confirmation-bypass sentences live in `larc_seraph/phrases.py`. `python tools/build_phrase_rules.py` writes them into the YARA rule, and `python tools/build_rule_flavors.py` writes both flavors. CI fails if either file drifts. A positive instruction fixture that the CLI matches and YARA does not also fails CI.

YARA descriptions start with `Detects `. Each YARA rule has `status` (`experimental` until there is fleet evidence) and `score` (an integer from 0 to 100). Names stay `SERAPH_*`. This pack does not add Neo23x0 category prefixes such as `MAL_` or `HKTL_`. Those prefixes classify malware families. The `SERAPH-YARA` / `SERAPH-SIGMA` id is the catalog key, and the three-digit number is unique across both families.

Sigma rules use the normalized macOS field contract: `Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`. They do not match raw Apple unified logs. Status stays `experimental` until there is fleet evidence. Do not widen a condition to make a failing fixture pass.

## Required metadata

Every YARA rule has these meta strings:

| Field | Shape |
| --- | --- |
| `author` | Person responsible for the rule |
| `date` | `YYYY-MM-DD`, first publication of the rule |
| `modified` | `YYYY-MM-DD` |
| `description` | Starts with `Detects ` |
| `reference` | `https://` URL. Extra URLs use `reference_2`, `reference_3` |
| `id` | `SERAPH-YARA-NNN`. The number is unique across YARA and Sigma |
| `status` | `experimental`, `test`, `stable`, or `deprecated` |
| `score` | Integer `0` through `100` |
| `version` | Rule version, such as `1.1.0` |
| `attack_technique` | ATT&CK technique ids, comma-separated: `T1059.004, T1105` |
| `attack_tactic` | ATT&CK tactic names, comma-separated |

`python tools/check_rule_metadata.py` fails the build when one of those is missing or malformed. The current rules also carry `title`, `organization`, `author_url`, `severity`, `scope`, `false_positives`, and `license`. Keep those on rules that already have them.

Every Sigma rule has:

| Field | Shape |
| --- | --- |
| `id` | UUID, unique in the pack |
| `status` | `experimental`, `test`, `stable`, `deprecated`, or `unsupported` |
| `level` | `informational`, `low`, `medium`, `high`, or `critical` |
| `tags` | At least one tag, including an `attack.*` tag |
| `logsource` | `product` and `category` |
| `falsepositives` | At least one entry |

Sigma rules in this pack also set `name` to the `SERAPH_` rule name, plus `title`, `description`, `author`, `date`, `references`, `license`, and `scope`.

`tests/test_rules.py` still requires the author string on every current rule to stay `Kevin Francis Tan` for YARA and `Kevin Francis Tan / Light Architects` for Sigma. A new rule under a different author has to update that assertion in the same pull request. Do not take an existing author off a rule you only edit.

## Fixtures

Put them under `tests/fixtures/yara/<RuleName>/` or `tests/fixtures/sigma/<RuleName>/`.

- `positive/` has at least one file that matches that rule and no other rule in the pack.
- `negative/` has at least one file that matches nothing in the pack.
- `tests/fixtures/yara/known_good/` and `tests/fixtures/sigma/known_good/` stay quiet.
- Sigma fixtures are JSON events on the normalized field contract.
- YARA fixtures are the file bytes. The harness passes the fixture path as `filepath`.

A pull request that adds a rule without both sides is incomplete.

## Tests locally

Python 3.11 or newer. `pytest` fails if `yarac` 4.5.x or the yara-x `yr` CLI is missing. CI builds libyara 4.5.4 and installs yara-x 1.23.0.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest
python tools/check_rule_metadata.py
sigma check --fail-on-issues --exclude d3_fendtag rules/sigma
yarac --fail-on-warnings --strict-escape rules/yara/*.yar /tmp/larc-forge.yac
yr compile rules/yara -o /tmp/larc-forge.yarc
yarac --fail-on-warnings --strict-escape -d filepath= rules/path-scoped/*.yar /tmp/larc-path.yac
python -m larc_seraph.docsgen --check
python tools/fp_scan.py
```

CI installs those libraries from `requirements/test.txt` with `--require-hashes` and `--only-binary :all:`. Regenerate that file with `pip-compile --extra test --generate-hashes --output-file requirements/test.txt pyproject.toml` when the test dependencies change.

`sigma check` downloads MITRE's ATT&CK STIX once. The `d3_fendtag` validator is excluded because this pack has no D3FEND tags and that validator downloads an ontology before it looks at the namespace.

`tools/fp_scan.py` clones a few public repositories and scans them. It does not execute the files. A hit that is not listed in `validation/fp-allowlist.txt` fails the command. The allowlist is empty on purpose. CI also fails the job when a clone fails or the scan sees fewer than 1000 files, so a silent empty corpus is not a pass.

Regenerate the static docs after a rule or write-up change:

```bash
python -m larc_seraph.docsgen
```

## Sign-off

Contributions use the [Developer Certificate of Origin](https://developercertificate.org/), version 1.1. Add the trailer with `git commit -s`:

```text
Signed-off-by: Your Name <you@example.com>
```

That line certifies you can submit the change under the project licenses: Apache-2.0 for code, tests, the scanner, and docs, and the Detection Rule License 1.1 for `rules/`. There is no separate CLA.

CI checks `Signed-off-by` on pull request commits. Merge commits are skipped. Do not rewrite published history to add a trailer.

CI also runs gitleaks on the git history. `.gitleaks.toml` keeps the default rules and ignores one false positive: a `SERAPH-SIGMA-NNN` or `SERAPH-YARA-NNN` id. Do not add a real credential to that allowlist.

## Releases

A maintainer tags `vX.Y.Z` on a commit that matches `version` in `pyproject.toml` and has a `CHANGELOG.md` section for that tag. The tag workflow runs the tests, builds the rules zip and tarball, writes `SHA256SUMS`, and publishes the GitHub Release. Do not push the tag from a pull request.
