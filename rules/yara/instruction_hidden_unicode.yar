/*
   SERAPH-YARA-006
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_Instruction_Hidden_Unicode
{
    meta:
        id = "SERAPH-YARA-006"
        title = "Instruction file contains Unicode tags or bidi overrides"
        author = "Kevin Francis Tan"
        organization = "Light Architects"
        author_url = "https://lightarchitects.ai"
        date = "2026-11-13"
        modified = "2026-11-13"
        version = "1.0.0"
        severity = "high"
        description = "A file contains Unicode tag characters (U+E0000 through U+E007F) or a bidi embedding or override control. Both are used to hide text from a human reader while leaving it in the bytes an agent will read."
        attack_technique = "T1027"
        attack_tactic = "defense-evasion"
        reference = "https://attack.mitre.org/techniques/T1027/"
        reference_2 = "https://www.unicode.org/charts/PDF/UE0000.pdf"
        reference_3 = "https://www.usenix.org/conference/usenixsecurity22/presentation/boucher"
        reference_4 = "https://atlas.mitre.org/techniques/AML.T0051"
        scope = "Agent instruction files such as AGENTS.md, CLAUDE.md, .cursorrules, and .github/copilot-instructions.md. The bytes are rare in ordinary prose, so the rule is content-wide."
        false_positives = "A linguistics note or a security write-up that embeds the raw controls on purpose. larc-seraph docs name the code points and do not embed them. Zero-width space and emoji joiners are intentionally not matched."
        license = "Detection Rule License 1.1"

    strings:
        // UTF-8 for U+E0000..U+E003F and U+E0040..U+E007F. The next scalar is U+E0080.
        $tag_lo = /\xf3\xa0\x80[\x80-\xbf]/
        $tag_hi = /\xf3\xa0\x81[\x80-\xbf]/
        // Trojan Source controls: LRE U+202A, RLE U+202B, LRO U+202D, RLO U+202E.
        $lre = { E2 80 AA }
        $rle = { E2 80 AB }
        $lro = { E2 80 AD }
        $rlo = { E2 80 AE }

    condition:
        any of them
}
