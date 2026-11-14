# MCP config places a secret environment variable on a network sink

## Threat

MCP servers often receive a token in an environment map so they can call their own vendor. That is normal. It is not normal for the command line to interpolate that variable into a URL, or to pipe the environment into a fetch utility.

## Why this rule

The rule requires the MCP server map and one of three shapes: a fetch utility followed by a `$NAME` or `${NAME}` for a short list of well-known token variables, the same interpolation inside a URL, or `printenv` piped into a fetch. An environment map that merely holds a placeholder token, with a local node command, is the negative. The dollar sign is the difference. The token list includes Gemini, Google, and Claude Code OAuth variables, each with its own vendor host. A token copied to another variable first, in the same string or the next argument, is followed to the fetch. A Node `fetch`, `axios`, `got`, or `https` call that reads `process.env` is a sink. A credential file piped or posted to a fetch utility matches.

## Limitations

The name list is finite. A custom variable will not match. A command that reads the token in a child process and posts it without those names will not match. A command that sends a named token to that vendor's own host does not match. A different host still does, including a lookalike such as `github.com.attacker.example`. An AWS secret has no vendor host and matches beside any URL. A token copied to a variable and then used in a fetch to a different host in the same string matches even if the fetch does not use the copy.

## Triage

The destination host matters more than the variable name. If the host is not the vendor that token belongs to, rotate the token and delete the entry.
