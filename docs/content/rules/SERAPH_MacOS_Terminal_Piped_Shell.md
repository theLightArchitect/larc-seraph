# macOS terminal parent started a shell that pipes a fetch or a decode

## Threat

SERAPH-SIGMA-015 only looks at agent parents. The same line typed in Terminal, iTerm, or a login shell is the gap that rule left open. Installers still teach people to pipe a fetch into a shell, and an unattended session can do it too.

## Why this rule

The parent path has to contain Terminal, iTerm, or login. The child has to be a shell or Python. The command line has to pipe curl, wget, or fetch into a shell, or call exec or eval on a base64 decode or on `urlopen`. A plain download does not match. A pytest run does not match. An agent parent does not match this rule; that remains SERAPH-SIGMA-015.

## Limitations

A parent path that merely contains the substring Terminal will match. A shell whose parent was recorded only as a pid will not, because the rule needs a path. Options hidden inside a script file that the command line does not quote are invisible here.

## Triage

An operator running an upstream install line is the expected false positive. Read the URL. If the operator is not at the keyboard, treat it as unattended execution.
