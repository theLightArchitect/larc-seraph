# MCP config launches a server from a temp or cache path

## Threat

An MCP client starts whatever command the config names. A durable install lives on a stable path. A command that points into a temp directory, a per-user cache, or shared memory is usually a file the operator did not install, or a script dropped there for one session and then kept.

## Why this rule

The rule requires the MCP server map, then either a command value whose path sits in that set, or a shell command whose argument string does. A filesystem server that is allowed to read a project directory does not match. A bare temp directory with no further path segment does not match either, because that shape is sometimes a legitimate directory grant.

## Limitations

A cache-installed CLI can be a real developer choice. Treat the match as a review of who put the file there. Homebrew prefixes are intentionally absent, so a shell in `/usr/local` or `/opt/homebrew` is a gap. The rule does not know whether the file at the path is still present.

## Triage

Read the command path. If the file is a scratch script the operator just wrote, note it and move on. If the path is unexpected, stop that MCP server and inspect who wrote the config.
