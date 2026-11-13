# macOS interpreter wrote a LaunchAgent or LaunchDaemon plist

## Threat

Creating the plist is the moment a login or boot job appears on disk. The content rules say whether the job is a shell in a user-writable path or an SSH tunnel. This rule says an interpreter wrote a plist under LaunchAgents or LaunchDaemons, which is the event you can see even when the file was deleted before a scanner reached it.

## Why this rule

The path has to contain one of the two launchd directories and end in `.plist`. The writer has to be a shell, Python, Node, osascript, or curl. `cp` dropping a plist does not match. A shell writing a README does not match. `/bin/sh` is matched as a suffix that does not also match `ssh`, which is a classic endswith footgun.

## Limitations

Severity is medium because installers and Homebrew casks drop LaunchAgents from shell scripts all day. Correlate with the plist content rules before you escalate. A writer that is a compiled helper, not an interpreter, does not match. The rule cannot see the plist body. That is the YARA rule's job.

## Triage

This event has no plist body. Pair it with the YARA launchd rules before escalating. Installers do this often.
