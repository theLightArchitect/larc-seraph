# Agent instructions request secret theft or skipped confirmation

## Threat

Instruction files are policy. Two policies are worth a look without any further context: a demand that the agent stop asking the operator, and a demand that a credential path or a well-known token name be sent to a network sink. A third shape pairs a sentence that tells the model to discard earlier directions with a sink or a token name. On its own, that sentence is a cliché. Next to a sink, it is a lead.

## Why this rule

The scanner passes `filepath`. The rule only then looks at instruction names and at JSON tool descriptions. A confirmation phrase has to be an instruction: a Markdown table row, a `--flag` on the same line, or an `ENV_VAR` token on the same line does not count. `auto-approve all tools` also needs an imperative cue such as "you must". A bypass that only covers a low-risk call such as `rename_chat` does not count. An unconstrained "do not ask for confirmation", or the same sentence next to a shell command, a delete, or a secret, still does. A credential and a network sink have to share a command line or one fenced block. A token sent to its own vendor host, and the word webhookSecret, do not count. A credential file or a token sent to a different host still does.

## Limitations

Natural language is easy to rephrase, and this rule will miss a rewrite. A team that truly wants agents to skip confirmation before a shell command, and writes that policy with the same phrases, will match. T1562.001 is an approximate mapping for "stop asking". A fenced block that uses tildes instead of backticks is not treated as one block. Only the first handful of phrase hits in a file are judged.

## Triage

Read the sentence in context. A team policy that really wants fewer prompts will say so in the open. A line that also names a credential path or a sink is the case to escalate.
