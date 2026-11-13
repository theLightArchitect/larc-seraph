# macOS SSH process opened a reverse tunnel with host-key checking disabled

## Threat

This is the running form of the plist rule. A reverse forward plus host-key checking disabled is the same pair of choices. The parent is intentionally not restricted to an agent host. A LaunchAgent's parent is launchd. Requiring Cursor or Claude on the parent would miss the persistence case the rule exists for.

## Why this rule

`Image` has to be ssh. The command line has to contain a reverse-forward flag surrounded by spaces, and one of the two spellings of the disabled host-key option. `accept-new` does not match. A disabled check on an ordinary git connection, with no reverse forward, does not match.

## Limitations

Operators do disable host-key checking on purpose. The false-positive note says that, and the severity stays high because the combination is still rare. Options stored in the user's ssh config, rather than on the command line, are invisible here. A reverse forward that uses `-R` glued to the next token, with no spaces, can miss the spaced-flag check.
