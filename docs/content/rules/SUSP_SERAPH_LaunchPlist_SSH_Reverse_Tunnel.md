# LaunchAgent plist opens an SSH reverse tunnel with host-key checking off

## Threat

A reverse forward makes a remote host reach back into this machine. Turning host-key checking off means the client will accept a changed or unknown key. Together, in a launchd job, that is a path in that does not depend on the operator being present and does not depend on the remote key staying the one that was trusted last time.

## Why this rule

The plist has to name ssh and a reverse forward, as `-R` or as `-o RemoteForward`, and a disabled host-key check, either as separate argument strings or as one command line. The check counts as disabled when StrictHostKeyChecking is no or off, or when it is `accept-new` and UserKnownHostsFile is `/dev/null`, since every host is then new. `accept-new` alone and the default checking mode do not match. A disabled check without a reverse forward does not match. The companion Sigma rule watches the running process, including when the parent is launchd rather than an editor.

## Limitations

An administrator who encodes this exact choice in a plist will match. The option can also be hidden in a config file that ssh reads by default, which this rule does not open. ATT&CK T1572 and T1021.004 describe the tunnel and the protocol. T1543.001 describes the persistence wrapper.

## Triage

This is a path in. Confirm with the operator whether they disabled host-key checking on purpose. If not, unload the job and review authorized_keys.
