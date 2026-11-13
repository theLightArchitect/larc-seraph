# MCP config places a secret environment variable on a network sink

## Threat

MCP servers often receive a token in an environment map so they can call their own vendor. That is normal. It is not normal for the command line to interpolate that variable into a URL, or to pipe the environment into a fetch utility.

## Why this rule

The rule requires the MCP server map and one of three shapes: a fetch utility followed by a `$NAME` or `${NAME}` for a short list of well-known token variables, the same interpolation inside a URL, or `printenv` piped into a fetch. An environment map that merely holds a placeholder token, with a local node command, is the negative. The dollar sign is the difference.

## Limitations

The name list is finite. A custom variable will not match. A command that reads the token in a child process and posts it without those names will not match. A proxy that really does forward one named token to its own vendor host will match, and the destination host is the thing to read.
