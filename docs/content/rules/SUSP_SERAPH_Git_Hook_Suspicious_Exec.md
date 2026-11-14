# Git hook decodes a payload, pipes a fetch into a shell, or posts a credential path

## Threat

Hooks run when the operator runs git. A repository the operator cloned can bring them along. The shapes worth a lead are the same ones that matter in a config: a fetch handed to a shell, a decode handed to a shell, or a network utility aimed at an SSH path, an authorized-keys file, or a LaunchAgents directory.

## Why this rule

Besides those, the rule reads a download to a file followed by a shell on a path in the same command, a fetch tool held in a variable and piped into a shell, a pipe placed on a backslash-continued line, a Python call that runs what a URL fetch returns, and a network utility with the .aws or .config/gh directories. A download sent to /dev/null does not count. A shebang is the scope, so a Markdown note about hooks does not match. A hook that only runs the test suite does not match. A hook that fetches a health URL and writes nothing sensitive does not match. The encoded positive decodes to the ASCII sentence `echo seraph-inert`. The network positive posts a key path to a reserved documentation host and does not contact it.

## Limitations

There is no ATT&CK sub-technique for Git hooks. T1546 is the parent, event-triggered execution, and the write-up should not pretend otherwise. A hook written in a language whose shebang is not in the list will miss. A network call that exfiltrates a token from the environment, without one of the path strings, will miss. A hook that only sources a second script holds no payload of its own, and the rule does not follow the file. A `.sample` hook is skipped on purpose by the path-scoped flavor. Read the URL on any match before you treat the hook as hostile. A download saved under a data file name such as .json or .txt is not read as a program, so a hook that downloads under such a name and then runs it will miss; the rule has no backreference to tell the downloaded file from another script. The .aws directory counts only as a path (~/.aws or $HOME/.aws), so a link to docs.aws.amazon.com or a comment does not.

## Triage

Do not run git commands in that clone until the hook is read. A hook that only runs the test suite does not match. One that posts a key path does.
