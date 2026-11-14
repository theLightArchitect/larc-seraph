# MCP config runs npx or uvx from a remote or floating tag

## Threat

`npx` and `uvx` will fetch code at start time. A registry package with a version is a choice you can pin. A URL, a `github:` or `gitlab:` specifier, a `git+` specifier, or a moving dist-tag such as `@latest` or `@next` is a choice that moves whenever the remote moves.

## Why this rule

The rule requires the MCP server map and one of those specifiers within a short window of `npx`, `uvx`, or `npm exec`. The official filesystem server invoked as a scoped package with no tag is a negative fixture. So is a package whose name contains the word github but not the `github:` specifier, and so is a version pin such as `@0.6.0`. The runners also include `uv tool run`, `pipx run`, and `deno run`. A first package argument of the form `user/repo` is read by npm as a GitHub repository. A `docker` image on `:latest` or a similar floating tag matches, and a numeric tag does not. A registry override such as `npm_config_registry=//host` is matched because it carries no scheme.

## Limitations

`@latest` is sometimes what an operator typed on purpose during a review. That branch is noisier than the URL branch, and the severity is still high because the shapes share one rule. Unpinned registry names with no tag are not matched. That omission is deliberate: it is the published quickstart, and a rule that flags it would train people to ignore the pack. A GitHub repository whose name contains a dot is not matched in the shorthand form. A private registry given with a scheme is a legitimate setup and is not matched. Track unpinned names with a lockfile policy, not with this signature. The GitHub shorthand is read only straight after the runner or after a flag from a closed list of flags that take no value (-y, --yes, --, --prefer-offline and similar). A shorthand placed after a flag that takes a value, such as --userconfig, will miss.

## Triage

The package specifier is the decision. A quoted URL, a github: specifier, or @latest means the code can change. Pin it or remove it.
