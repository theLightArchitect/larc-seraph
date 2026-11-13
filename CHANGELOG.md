# Changelog

## v0.1.1 — 2026-11-13

Scope tuning after a real Mac scan of 70,470 files. `yr` and libyara agreed on every hit, and 264 of them were benign.

- Hidden Unicode and Unsafe Directive now match only instruction paths and JSON MCP tool descriptions, and they skip binaries. Subdivision-flag emoji sequences are not hidden-text hits.
- Unsafe Directive no longer treats `--yes` / `-y` help text as an instruction to skip confirmation.
- The git-hook rule requires `.git/hooks/` or `.husky/` and ignores `*.sample`.
- MCP rules match JSON, TOML, and YAML configs, not Markdown examples.
- Rewrote the two patterns libyara 4.5 warned were slow, so `yarac --fail-on-warnings` is clean.
- Copies of the pack's own positive fixtures, including editor file-history copies, are expected matches. Those 12 hits were left as true positives.

## v0.1.0 — 2026-11-13

First named release of larc-seraph, the Light Architects detection pack for AI-agent tooling on developer workstations. Author: Kevin Francis Tan.

- The pack name is larc-seraph. Rule IDs are unchanged: `SERAPH-YARA-001` through `SERAPH-YARA-016`, and `SERAPH-SIGMA-011` through `SERAPH-SIGMA-016`.
- Closed the dictionary-form `KeepAlive` gap, added an unpinned npx/uvx rule, added a Terminal and iTerm piped-shell rule, and widened confirmation-bypass matching for spacing, one zero-width mark, and Cyrillic `o`.
- Added eslogger, Elastic Common Schema, and osquery normalizers, plus Lucene and Splunk conversions.
- Recorded the benign-corpus scan and the evasion matrix in `VALIDATION.md`.

The repository stays private. This changelog entry is not a public release.
