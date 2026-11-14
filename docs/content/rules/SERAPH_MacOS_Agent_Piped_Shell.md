# macOS agent parent started a shell that pipes a fetch or a decode

## Threat

The content rules catch this shape when it is written into a config or a hook. This rule catches it when an agent host actually spawns it. The parent matters. The same command typed in Terminal is a different problem, and it is out of scope so the rule stays about agent tooling.

## Why this rule

The parent image has to be an agent host. The child has to be a shell or Python. The command line has to pipe a fetch or a base64 invocation into a shell, or it has to call `exec` or `eval` on a base64 decode. A plain download from an agent does not match. A decode that only prints does not match. The same command from Terminal does not match.

## Limitations

A LaunchAgent that later runs the same command has launchd as its parent, not the agent, so this rule will not see it. Use the plist rules for that stage. The python branch looks for `exec(` or `eval(` next to a decode call. Other interpreters are a gap. As with the rest of the Sigma set, the fields have to be the normalized contract or the rule is inert.

## Added in the hardening round

The rule now also matches a pipe followed by two spaces, a fetch followed by a tab, a pipe into a bare `python3` (not `python3 -m json.tool` or `python3 -c`), a fetch run through a shell command substitution or process substitution (`sh -c "$(curl ...)"`, `eval "$(curl ...)"`, `sh <(curl ...)`), a fetch followed by running a file from a temp directory, and osascript as the child. A plain `$(curl ...)` assigned to a variable does not match. A node parent is not accepted: every npm script and JS tool has one, so it says nothing about an agent. That is an asserted miss in `validation/evasion-matrix.yml`.

## Triage

Read the URL and the parent. The same line typed into Terminal is not covered by this pack. A single exec event does not hold a pipeline that an interactive shell parsed.
