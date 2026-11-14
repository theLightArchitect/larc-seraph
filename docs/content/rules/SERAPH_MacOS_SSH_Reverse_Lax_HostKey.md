# macOS SSH process opened a reverse tunnel with host-key checking disabled

## Threat

This is the running form of the plist rule. A reverse forward plus host-key checking disabled is the same pair of choices. The parent is intentionally not restricted to an agent host. A LaunchAgent's parent is launchd. Requiring Cursor or Claude on the parent would miss the persistence case the rule exists for.

## Why this rule

`Image` has to be ssh or autossh. The command line has to contain a reverse forward (`-R`, alone, in a cluster such as `-NR`, or glued to its value, or `RemoteForward`) and the disabled host-key option, spelled `no` or `off`. `accept-new` does not match. A disabled check on an ordinary git connection, with no reverse forward, does not match.

## Limitations

Operators do disable host-key checking on purpose. The false-positive note says that, and the severity stays high because the combination is still rare. Options stored in the user's ssh config, rather than on the command line, are invisible here. A reverse forward that uses `-R` glued to the next token, with no spaces, can miss the spaced-flag check.

## Added in the hardening round

`StrictHostKeyChecking=accept-new` combined with `UserKnownHostsFile=/dev/null` now matches, because nothing is ever remembered. `accept-new` alone still does not. A tab between flags is read the same as a space. Options held in a `-F` config file stay invisible, and that is an asserted miss in `validation/evasion-matrix.yml`.

## Triage

Confirm the parent. launchd means a persistent job. An interactive shell may be an operator running a tunnel on purpose.
