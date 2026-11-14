# LaunchAgent plist runs a shell from a user-writable path

## Threat

A LaunchAgent with RunAtLoad starts at login. Boolean KeepAlive starts it again if it exits. Pointed at a shell and a script under the home directory, a temp directory, or a cache, that is a persistence job whose payload the user, or anything running as the user, can rewrite.

## Why this rule

All four pieces have to be present: the plist marker, RunAtLoad true, KeepAlive as a boolean, a dictionary or a non-zero integer, a shell or interpreter in its own argument string, and a user-writable path in an argument string. The rule reads three encodings of the same plist: XML, UTF-16 XML, and the binary format that starts with bplist00. In XML, a comment between a key and its value is skipped and a slash written as a numeric character reference is read as a slash. In the binary format the key names, an interpreter string and a writable path must all be present, and the rule does not read whether the values are true. A helper under `/usr/libexec` does not match. Node installed on a system prefix, running a script that is also on that prefix, does not match. Homebrew paths were left out so ordinary package-manager jobs are not the signal.

## Limitations

KeepAlive as a dictionary is in scope, and so is a non-zero integer. RunAtLoad with no KeepAlive, a timer in place of KeepAlive, a user-path binary with no interpreter, and a script under /opt do not match, because ordinary login items look the same. Entities for letters inside the interpreter path are not decoded, and UTF-16 big-endian is not read. An inline shell command with no user-writable path does not match; the SSH rule covers one important case of that shape. A developer who really does reload a personal script at login will match, and that is a review, not an automatic incident.

## Triage

Do not load the plist. Check the script it names, then remove the job if the operator did not create it. Dictionary-form KeepAlive is in scope.
