# MCP config runs an unpinned npx or uvx package

## Threat

`npx` and `uvx` will fetch a package at start time when the config does not pin a version. SERAPH-YARA-004 covers URLs, `github:` specifiers, and `@latest`. This rule covers the quieter case: a registry name with no version at all.

## Why this rule

The command has to be npx, uvx, or bunx inside an MCP server map. A bare name, or a scoped name, matches when that package token has no numeric version. `@modelcontextprotocol`, `@anthropic-ai`, and `@github` are allowlisted on the matched entry, not for the whole file. A community scope such as `@example/tool` matches. A `name@1.2.3` pin, or a stray `node@1.2` elsewhere in the file, does not clear a second unpinned package. Other flags between `-y` and the package do not hide it, the runner may sit behind `cmd /c` or inside a `sh -c` string that uses `-y`, and `pnpm dlx`, `npm exec`, and `uv tool run` count as runners. A `--package=name` argument without a version matches. A range such as `@^1` is not a pin.

## Limitations

The allowlist is a choice, not a proof of integrity. A package on an allowlisted scope can still be the wrong package. A pin has to be on the package token itself. A dist-tag such as `@next` is SERAPH-YARA-004 and a numeric pin is never matched here, even the registry's security placeholder version. A shell string without `-y` is not matched, so a local `npx tsc` stays quiet. Upstream READMEs that show `uvx mcp-server-time` match, and that hit is recorded in the benign-corpus report.

## Triage

This is a hygiene lead, not a compromise by itself. Pin the package or confirm it is on the allowlist. Upstream READMEs that show an unpinned uvx command will match.
