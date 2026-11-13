# macOS node or npm started an AI CLI with a skip-permission flag

## Threat

The August 2025 Nx s1ngularity payload, running from a malicious npm release, started local AI CLIs with the flags that turn permission prompts off. Snyk, Wiz, and StepSecurity published the command lines: `claude --dangerously-skip-permissions`, `gemini --yolo`, and `q chat --trust-all-tools`. The stolen inventory then went to public GitHub repositories named `s1ngularity-repository`.

## Why this rule

The parent has to be `node`, `npm`, or `npx`. The child has to be `claude`, `gemini`, `q`, or `codex`. The command line has to contain one of those three flags. A person who types the same flag into zsh or Terminal does not match. `codex` was not in the published payload. It is here because it is the same class of CLI and the same flag.

## Limitations

A developer who really wants a node script to launch Claude with prompts disabled will match. The rule cannot see a flag that was passed through an environment variable or a response file. `Image` ending in `/q` is the Amazon Q CLI name from the incident. A different binary with that exact filename would match too.

## Triage

Read the parent and the command line. An npm install that just finished, plus one of these flags, is the s1ngularity shape. A node test harness the team wrote on purpose is the false-positive note.
