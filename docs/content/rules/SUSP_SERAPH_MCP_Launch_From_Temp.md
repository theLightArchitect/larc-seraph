# MCP config launches a server from a temp or cache path

## Threat

An MCP client starts whatever command the config names. A durable install lives on a stable path. A command that points into a temp directory, a per-user cache, or shared memory is usually a file the operator did not install, or a script dropped there for one session and then kept.

## Why this rule

The rule requires the MCP server map, then either a command value whose path sits in that set, or a shell command whose argument string does. A filesystem server that is allowed to read a project directory does not match. A bare temp directory with no further path segment does not match either, because that shape is sometimes a legitimate directory grant. A bare shell or env name counts as the launcher as well as an absolute one, a script run by a command word inside one shell string counts, and so does Zed's nested command path. `/Users/Shared` is on the path list because every local user can write there. A `.` segment or a JSON-escaped slash in the path does not hide it.

## Limitations

A cache-installed CLI can be a real developer choice. Treat the match as a review of who put the file there. Homebrew prefixes are intentionally absent, so a shell in `/usr/local` or `/opt/homebrew` is a gap. The rule does not know whether the file at the path is still present. A bare python or osascript name is not a launcher here, because a data directory under `/tmp` is common beside it. A temp path right after a flag that takes a value (bash --rcfile /tmp/x.sh) is read as data and will miss, as is a path that ends in a slash. The -c flag is not on that list, because sh -c /tmp/x runs the file.

## Triage

Read the command path. If the file is a scratch script the operator just wrote, note it and move on. If the path is unexpected, stop that MCP server and inspect who wrote the config.
