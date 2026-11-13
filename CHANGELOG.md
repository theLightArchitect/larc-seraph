# Changelog

## v0.1.0 — 2026-11-13

First named release of larc-seraph, the Light Architects detection pack for AI-agent tooling on developer workstations. Author: Kevin Francis Tan.

- The pack name is larc-seraph. Rule IDs are unchanged: `SERAPH-YARA-001` through `SERAPH-YARA-016`, and `SERAPH-SIGMA-011` through `SERAPH-SIGMA-016`.
- Closed the dictionary-form `KeepAlive` gap, added an unpinned npx/uvx rule, added a Terminal and iTerm piped-shell rule, and widened confirmation-bypass matching for spacing, one zero-width mark, and Cyrillic `o`.
- Added eslogger, Elastic Common Schema, and osquery normalizers, plus Lucene and Splunk conversions.
- Recorded the benign-corpus scan and the evasion matrix in `VALIDATION.md`.

The repository stays private. This changelog entry is not a public release.
