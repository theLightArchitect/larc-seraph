# macOS agent process wrote SSH authorized_keys

## Threat

`authorized_keys` is the list of keys allowed to log in. An editor, a model, or an MCP server does not manage that file in the normal course of writing code. When a process whose path matches a known agent host writes it, the session has crossed from the workspace into SSH trust.

## Why this rule

The file path has to end in `authorized_keys` or `authorized_keys2`. The image or the parent image has to contain one of the reviewed agent-host substrings. A person editing the file in vim from Terminal does not match. An agent writing a README does not match. The same marker list is shared with the shell-rc rule and the piped-shell rule, and a test fails if they drift.

## Limitations

The rule is only as current as the host list. A follow-on write by a shell whose parent is launchd, after a LaunchAgent has already been installed, does not match this rule. That case belongs with the plist rules. A dotfile tool whose path happens to contain one of the substrings will match. The field names are the larc-seraph contract. A collector that does not supply `ParentImage` can still match on `Image` alone, and will miss the case where only the parent is the agent.

## Added in the hardening round

The rule also covers `~/.ssh/authorized_keys.d/` files, Windsurf, and the opencode, aider, and goose binaries. A node image or a node parent counts as an agent host for this target only, because Gemini CLI and similar agents run as node scripts and writing authorized_keys from node is not ordinary developer activity. Three shapes stay open. A writer whose grandparent is the agent is invisible, because one event carries no grandparent. A write through a symlink reports the target path, not the authorized_keys name. A write to `~/.ssh/config` is left out because agents edit it as routine work. Each one is an asserted miss in `validation/evasion-matrix.yml`.

## Triage

Diff the keys file. If the operator asked for a bootstrap key, record that. If not, remove the new line and rotate access.
