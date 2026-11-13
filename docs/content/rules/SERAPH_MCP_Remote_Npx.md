# MCP config runs npx or uvx from a remote or floating tag

## Threat

`npx` and `uvx` will fetch code at start time. A registry package with a version is a choice you can pin. A URL, a `github:` specifier, a `git+` specifier, or an explicit `@latest` tag is a choice that moves whenever the remote moves.

## Why this rule

The rule requires the MCP server map and one of those specifiers within a short window of `npx`, `uvx`, or `npm exec`. The official filesystem server invoked as a scoped package with no tag is a negative fixture. So is a package whose name contains the word github but not the `github:` specifier, and so is a version pin such as `@0.6.0`.

## Limitations

`@latest` is sometimes what an operator typed on purpose during a review. That branch is noisier than the URL branch, and the severity is still high because the two shapes share one rule. Unpinned registry names with no tag are not matched. That omission is deliberate: it is the published quickstart, and a rule that flags it would train people to ignore the pack. Track those with a lockfile policy, not with this signature.

## Triage

The package specifier is the decision. A quoted URL, a github: specifier, or @latest means the code can change. Pin it or remove it.
