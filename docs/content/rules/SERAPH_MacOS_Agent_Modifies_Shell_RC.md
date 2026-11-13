# macOS agent process modified a user shell rc file

## Threat

Shell startup files run in later interactive sessions. An alias or a PATH edit is a common, legitimate request to an agent. It is also a place to hide a command the operator will not see until the next terminal. The severity is medium because the legitimate case is common.

## Why this rule

The target has to be one of the usual user startup files, and the image or parent has to be an agent host from the shared list. Vim editing `.zshrc` from Terminal is a negative. An agent writing a project README is a negative. An npx-cached node binary writing `.bashrc` is a positive, because that path is how an unpinned MCP server shows up on disk.

## Limitations

Project-level rc files and unusual startup names are not in the list. The legitimate "add this alias" request will match, and the note on the rule says so. Do not page on this rule alone. Read the diff.
