# Agent instructions request secret theft or skipped confirmation

## Threat

Instruction files are policy. Two policies are worth a look without any further context: a demand that the agent stop asking the operator, and a demand that a credential path or a well-known token name be sent to a network sink. A third shape pairs a sentence that tells the model to discard earlier directions with a sink or a token name. On its own, that sentence is a cliché. Next to a sink, it is a lead.

## Why this rule

The sentence list lives in `larc_seraph.phrases`. `tools/build_phrase_rules.py` writes those sentences into this YARA rule, so a YARA-only scanner and the CLI match the same fixtures. The rule ignores a Markdown table row, a heading, a known permission flag such as `--yolo`, and a bypass that only covers a read-only action. A zero-width mark may sit between the words. A token sent to its own vendor host does not count.

## Limitations

Natural language is easy to rephrase, and this rule will miss a rewrite. A team that truly wants agents to skip confirmation before a shell command, and writes that policy with the same phrases, will match. T1562.001 is an approximate mapping for "stop asking". A fenced block that uses tildes instead of backticks is not treated as one block. Only the first handful of phrase hits in a file are judged.

## Triage

Read the sentence in context. A team policy that really wants fewer prompts will say so in the open. A line that also names a credential path or a sink is the case to escalate.
