# The agent on the workstation

larc-seraph is a detection pack for a change in who acts on a developer machine. The files below are the threat model and the method. They are short on purpose.

## What changed

A developer workstation already holds source, signing keys, cloud tokens, and SSH trust. An agent product adds a local principal that reads instruction files and tool configs, then acts with the operator's privileges. The operator still sits in the chair. The judgment about what to run has moved into a model plus whatever text that model was given.

That text is often a file in the repo or a JSON config in an application support directory. Those used to be boring. They are now part of the control plane.

larc-seraph watches that control plane. It does not block, quarantine, or claim to see every agent product. A match is a lead for a person.

[[surface]]

## Assets

The interesting assets are the ones an agent can touch without a new privilege:

- Source trees, including private code that is sitting in a chat or a prompt file.
- SSH private keys, `authorized_keys`, and agent sockets.
- Cloud and API tokens in the environment or in dotfiles.
- Shell startup files, which run again in the next interactive session.
- Launch agents, which run after the editor has quit.
- Git hooks, which run when the operator types an ordinary git command.

## Trust boundaries

Four files, or file classes, used to sit outside the security model because a person wrote them and a person could read them.

1. The MCP client config decides which process starts, from which path, with which environment.
2. Instruction files (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`) decide what the model is told to treat as policy.
3. Git hooks are code the operator runs by using git.
4. Launch agents and launch daemons are code that survives the session.

The agent process is inside the user boundary. A detection that treats "the user did it" as benign will miss the case where the user is a model following a file. Parentage and file content are the useful questions. The username is not.

## Goals, not procedures

The goals this pack is built around are ordinary:

- Keep running after the agent session ends.
- Read a credential and move it to another host.
- Open a path back in, including a tunnel that does not check host keys.
- Persuade the agent to stop asking the operator before it acts.
- Replace a pinned tool with a package that is fetched by URL or a floating tag.

larc-seraph does not publish the steps for those goals. The rules name the shapes that show up in files and in process events when someone pursues them.

## What the rules watch

| Surface | Engine | Question |
| --- | --- | --- |
| MCP client config | YARA | Is the configured command a temp path, a fetch piped into a shell, an encoded exec, a remote package specifier, or a token variable on a URL? |
| Instruction file | YARA | Are there hidden Unicode controls, or prose that skips confirmation, or a credential path next to a network sink? |
| Launchd plist | YARA | Does a login job combine a shell, a user-writable path, and restart flags, or an SSH reverse forward with host-key checking off? |
| Git hook | YARA | Does a hook script decode into a shell, pipe a fetch into a shell, or send a credential path over the network? |
| File and process events | Sigma | Did an agent host write SSH trust or a shell rc file, did an interpreter drop a plist, or did an agent parent start a piped shell? |

The content rules can fire before anything executes. The event rules can fire when nobody scanned the file. They are complementary. Neither is sufficient.

## Field contract

Sigma has no native Apple schema. larc-seraph rules assume a translator has already mapped Endpoint Security exec and file events onto these names:

- `Image` — absolute path of the process executable.
- `CommandLine` — the argument string.
- `ParentImage` — absolute path of the parent executable.
- `TargetFilename` — absolute path of a file that was created or written.
- `User` — the effective user. Present for the analyst. Not required by the conditions.

Unified logs, osquery, and commercial endpoint agents can all feed this shape, but only after a mapping. larc-seraph ships normalizers for eslogger JSON, Elastic ECS, and osquery rows, plus pySigma pipelines that emit Lucene and Splunk queries in those field names. A pipeline that omits `ParentImage` will not fire the rules that use ancestry. That is a collector gap, not a silent success.

The agent-host substrings are a reviewed list, shared by the rules that need it: Cursor, Claude, codex, the npx cache, and VS Code's Code Helper. A new agent host does not match until someone adds it. A path that merely contains those substrings can false-positive. Both facts are in the rule notes.

## What a match means

Status is `experimental` on every rule. The pytest suite proves three things: the rule compiles, the synthetic positive matches that rule and no other rule in the pack, and the synthetic negatives match nothing. It does not prove a false-positive rate on a fleet. Do not auto-quarantine on this version.

Read the false-positive note before you page someone. Several rules describe habits that a careful operator sometimes chooses on purpose, including a login script under the home directory and an SSH option that disables host-key checking.

## What this pack does not claim

- Coverage of every agent, IDE, or MCP client. The list is the one in the rules.
- Detection of instructions that have been rephrased. Natural language is soft. The instruction rules are high-signal phrases plus a structural scope, and they will miss a rewrite.
- A hit on the common `npx -y @scope/package` quickstart with no tag. That pattern is the published way to start several official servers, so it is a known-good in this pack. Remote specifiers and an explicit floating tag are in scope. Unpinned registry packages are a supply-chain hygiene problem and a different rule, which this version refuses to pretend it can block cleanly.
- A fetch piped into a shell from Terminal, when the parent is not an agent host. That behavior is bad and it is out of scope here, because it is not specific to agent tooling. Other packs already cover it.
- Dictionary-form `KeepAlive` in a plist. The launchd content rule looks for a boolean.
- Memory-only tradecraft, encrypted blobs with no decode step, or a model that never writes the instruction down.
- Windows or Linux endpoint content. The workstation in the model is a Mac because that is where the launchd and ESF questions are specific. The YARA file rules are still useful on any OS if you point them at the same filenames.
- A production EDR. There is a small local scanner so a reviewer can try a file. It does not ship telemetry.

## How a test earns its sentence

`pytest` compiles the YARA set, evaluates every Sigma rule with the same condition semantics pySigma parsed, and requires the fixture truth table above. It also runs `sigma check --fail-on-issues`, checks author, date, license, and ATT&CK metadata, and checks that the HTML site matches these sources. A green run means the pack is internally consistent. It does not mean the detections are finished.

## Adding a rule

One rule, one severity, both a positive and a negative fixture, and a write-up with the threat, why the logic holds, and where it fails. Then `pytest` and `python -m larc_seraph.docsgen`. If the negative also matches some other rule, the fixture is wrong or the rules overlap more than the catalog admits. Overlap should be explicit.

## License

Code, the test harness, the scanner, and these pages are Apache-2.0. The rules under `rules/` are Detection Rule License 1.1. DRL is the license detection engineers already pass around: you may use and ship the rules, including inside a product, and you keep the author attribution. CC-BY-4.0 was the other reasonable choice. It is easier to explain and worse as a signal to someone merging a Sigma rule into an existing ruleset. Kevin Francis Tan can relicense either half. Nothing here is assigned to a foundation.

Author: Kevin Francis Tan, Light Architects, lightarchitects.ai. Date of this version: 2026-11-13.
