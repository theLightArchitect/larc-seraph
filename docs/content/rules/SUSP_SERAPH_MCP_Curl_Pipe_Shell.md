# MCP config pipes a remote fetch into a shell

## Threat

The configured server is supposed to be a program. A one-liner that downloads a script and hands it to a shell is an installer, not a server, and the bytes that run are chosen by the remote host at start time.

## Why this rule

The rule looks for a fetch utility on the same line as a pipe into a shell, or a process substitution that feeds a fetch into a shell, inside a file that also carries the MCP server map. A download that writes a file and stops does not match. The positive fixtures use a reserved documentation host and do not retrieve anything. A bare `python3`, `node`, `perl`, or `ruby` after the pipe is a sink, because it reads the fetched script from standard input; an interpreter with a script or module argument is not. A fetch written to a file and run by a shell in the same string matches. httpie and xh count as fetch utilities.

## Limitations

Splitting the fetch and the shell across two processes, or across separate strings, misses. A fetch that is run through a variable that expands to the utility name misses. Quoting the anti-pattern inside a long description on the same line as a real fetch can false-positive. This is a content rule: it says the config contains the shape, not that the process ran.

## Triage

Read the URL before you treat the entry as hostile. If the operator pasted an upstream install line, that is the documented false positive. Otherwise remove the server entry and review the rest of the config.
