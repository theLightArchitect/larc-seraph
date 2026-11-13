# Instruction file contains Unicode tags or bidi overrides

## Threat

Agent instruction files are read by a model and, usually, glanced at by a person. Unicode tag characters (U+E0000 through U+E007F) are invisible in ordinary rendering and can carry a second sentence. Bidi overrides (U+202A, U+202B, U+202D, U+202E) reorder the characters a person sees relative to the characters the parser reads. Both are established ways to hide text. The Trojan Source paper documents the bidi case. MITRE ATLAS AML.T0051 is the prompt-injection class this supports. ATT&CK T1027 is the closest enterprise technique, and it is only an approximation.

## Why this rule

The rule matches the UTF-8 ranges for the tag block and the four bidi override bytes. It does not match zero-width space, word joiner, or emoji joiners. Those show up in ordinary text. Tag characters and bidi overrides almost never do. The positive fixtures are labelled, one with a tag-encoded inert word and one with a single override at the end of the file so the heading stays readable.

## Limitations

A write-up that embeds the raw controls on purpose will match. larc-seraph's own pages name the code points and do not embed them. A motivated author can hide instructions with homoglyphs or with wording alone, and this rule will not see that. Path-scope the scan to instruction filenames if you do not want it running across arbitrary binaries, where a random byte sequence is more plausible.

## Triage

Open the file in a hex view. If the hidden bytes are a quote in a security note, the false-positive note applies. If they are not, treat the file as untrusted instructions and remove it from the agent path.
