# LaunchAgent plist runs a shell from a user-writable path

## Threat

A LaunchAgent with RunAtLoad starts at login. Boolean KeepAlive starts it again if it exits. Pointed at a shell and a script under the home directory, a temp directory, or a cache, that is a persistence job whose payload the user, or anything running as the user, can rewrite.

## Why this rule

All four pieces have to be present: the plist marker, RunAtLoad true, KeepAlive true, a shell or interpreter in its own argument string, and a user-writable path in an argument string. A helper under `/usr/libexec` does not match. Node installed on a system prefix, running a script that is also on that prefix, does not match. Homebrew paths were left out so ordinary package-manager jobs are not the signal.

## Limitations

KeepAlive expressed as a dictionary, which launchd allows, does not match. That negative fixture is in the pack so the gap stays visible. An inline shell command with no user-writable path does not match either; the SSH rule covers one important case of that shape. A developer who really does reload a personal script at login will match, and that is a review, not an automatic incident.
