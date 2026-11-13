# MCP config pipes a remote fetch into a shell

## Threat

The configured server is supposed to be a program. A one-liner that downloads a script and hands it to a shell is an installer, not a server, and the bytes that run are chosen by the remote host at start time.

## Why this rule

The rule looks for a fetch utility on the same line as a pipe into a shell, or a process substitution that feeds a fetch into a shell, inside a file that also carries the MCP server map. A download that writes a file and stops does not match. The positive fixtures use a reserved documentation host and do not retrieve anything.

## Limitations

Splitting the fetch and the shell across two processes, or across a line break, misses. Quoting the anti-pattern inside a long description on the same line as a real fetch can false-positive. This is a content rule: it says the config contains the shape, not that the process ran.
