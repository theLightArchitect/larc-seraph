# macOS node or npm started an AI CLI with a skip-permission flag

## Threat

The August 2025 Nx s1ngularity payload, running from a malicious npm release, started local AI CLIs with the flags that turn permission prompts off. Snyk, Wiz, and StepSecurity published the command lines: `claude --dangerously-skip-permissions`, `gemini --yolo`, and `q chat --trust-all-tools`. The stolen inventory then went to public GitHub repositories named `s1ngularity-repository`.

## Why this rule

The parent has to be a JavaScript runtime or package manager: `node`, `npm`, `npx`, `pnpm`, `yarn`, `bun`, or `deno`. `/bin/sh` also counts, because `child_process.exec` puts a shell between node and the CLI. The child is named by its image (`claude`, `gemini`, `q`, `codex`, or Claude's versioned install path) or by the script path in the command line (including `claude-code/cli.js`), because `gemini` and `codex` are node scripts and the executed image is `node`. The command line has to carry one of the three published flags or an equivalent: `--permission-mode bypassPermissions`, `--approval-mode yolo`, `gemini -y`, or `--dangerously-bypass-approvals-and-sandbox`. A person who types the same flag into zsh or bash does not match. `codex` was not in the published payload. It is here because it is the same class of CLI.

## Limitations

A developer who really wants a node script to launch Claude with prompts disabled will match, and so will a `/bin/sh` script that does it. The script-path and versioned-image shapes come from the installed CLIs, not from a captured event. `q chat -a`, `copilot --allow-all-tools`, and `cursor-agent --force` are not in the rule. The rule cannot see a flag that was passed through an environment variable or a response file. `Image` ending in `/q` is the Amazon Q CLI name from the incident. A different binary with that exact filename would match too.

## Triage

Read the parent and the command line. An npm install that just finished, plus one of these flags, is the s1ngularity shape. A node test harness the team wrote on purpose is the false-positive note.
