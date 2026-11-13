# Git hook decodes a payload, pipes a fetch into a shell, or posts a credential path

## Threat

Hooks run when the operator runs git. A repository the operator cloned can bring them along. The shapes worth a lead are the same ones that matter in a config: a fetch handed to a shell, a decode handed to a shell, or a network utility aimed at an SSH path, an authorized-keys file, or a LaunchAgents directory.

## Why this rule

A shebang is the scope, so a Markdown note about hooks does not match. A hook that only runs the test suite does not match. A hook that fetches a health URL and writes nothing sensitive does not match. The encoded positive decodes to the ASCII sentence `echo seraph-inert`. The network positive posts a key path to a reserved documentation host and does not contact it.

## Limitations

There is no ATT&CK sub-technique for Git hooks. T1546 is the parent, event-triggered execution, and the write-up should not pretend otherwise. A hook written in a language whose shebang is not in the list will miss. A network call that exfiltrates a token from the environment, without one of the path strings, will miss. Read the URL on any match before you treat the hook as hostile.
