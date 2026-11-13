# Agent instructions request secret theft or skipped confirmation

## Threat

Instruction files are policy. Two policies are worth a look without any further context: a demand that the agent stop asking the operator, and a demand that a credential path or a well-known token name be sent to a network sink. A third shape pairs a sentence that tells the model to discard earlier directions with a sink or a token name. On its own, that sentence is a cliché. Next to a sink, it is a lead.

## Why this rule

The file has to look like instructions first: a Markdown heading at the start, or a line that begins "You are a" or "You are an". That keeps shell scripts and JSON configs out of the rule. Inside that scope, the rule matches a short list of confirmation-bypass phrases, or a credential path and a fetch utility within 400 characters, or the override sentence within 400 characters of a sink or a token name. A policy that says to ask first, including one that mentions a token name and tells the reader not to merge without a check, is a negative. So is the same pair of ideas placed far apart.

## Limitations

Natural language is easy to rephrase, and this rule will miss a rewrite. A team that truly wants agents to skip confirmation, and writes that policy with the same phrases, will match. T1562.001 is an approximate mapping for "stop asking"; the enterprise technique is about impairing security tools. Read the sentence before you call it malice. Heading-less instruction files that also avoid the "You are" opening are a gap. Point the scanner at the known filenames anyway.

## Triage

Read the sentence in context. A team policy that really wants fewer prompts will say so in the open. A line that also names a credential path or a sink is the case to escalate.
