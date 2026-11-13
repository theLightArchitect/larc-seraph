/*
   SERAPH-YARA-006
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.

   Scanners must pass the external string filepath with forward slashes.
   An empty filepath does not match this rule.
*/

rule SERAPH_Instruction_Hidden_Unicode_Path {
  meta:
    id               = "SERAPH-YARA-006-PATH"
    title            = "Instruction file contains Unicode tags or bidi overrides"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.5.0"
    severity         = "high"
    status           = "experimental"
    score            = "80"
    description      = "Detects Unicode tag characters or a bidi override in an instruction file. The three subdivision flags Unicode recommends (England, Scotland, Wales) are ignored. Every tag character is checked, however many flags come first. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1027"
    attack_tactic    = "defense-evasion"
    reference        = "https://attack.mitre.org/techniques/T1027/"
    reference_2      = "https://www.unicode.org/charts/PDF/UE0000.pdf"
    reference_3      = "https://www.usenix.org/conference/usenixsecurity23/presentation/boucher"
    reference_4      = "https://atlas.mitre.org/techniques/AML.T0051"
    reference_5      = "https://securityaffairs.com/175593/hacking/rules-file-backdoor-ai-code-editors-silent-supply-chain-attacks.html"
    reference_6      = "https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"
    scope            = "AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .cursor/rules/*, SKILL.md, copilot-instructions.md, and JSON MCP configs, any case. Set filepath to the path as stored. The England, Scotland, and Wales flag sequences are skipped. Zero-width characters, bidi isolates (U+2066 to U+2069), and variation selectors are not in this rule."
    false_positives  = "An instruction file that embeds the raw controls on purpose. larc-seraph docs name the code points and do not embed them."
    license          = "Detection Rule License 1.1"

  strings:
    // UTF-8 for U+E0000..U+E007F. Hex atoms stay inside the fast path.
    $tag  = { F3 A0 (80 | 81) ?? }
    // U+1F3F4, tag g, tag b, then eng, sct, or wls, then the cancel tag U+E007F.
    // These three are the only subdivision flags in Unicode's RGI emoji set.
    // A black flag followed by any other tag run is not exempt.
    $flag = { F0 9F 8F B4 F3 A0 81 A7 F3 A0 81 A2 (F3 A0 81 A5 F3 A0 81 AE F3 A0 81 A7 | F3 A0 81 B3 F3 A0 81 A3 F3 A0 81 B4 | F3 A0 81 B7 F3 A0 81 AC F3 A0 81 B3) F3 A0 81 BF }
    $desc = "\"description\"" ascii
    // Trojan Source controls: LRE U+202A, RLE U+202B, LRO U+202D, RLO U+202E.
    $lre  = { E2 80 AA }
    $rle  = { E2 80 AB }
    $lro  = { E2 80 AD }
    $rlo  = { E2 80 AE }

  condition:
    filesize > 0 and filesize < 5000000 and
    (
      filepath matches /(\/(agents|claude|gemini)\.md$)|(\/\.cursorrules$)|(\/skill\.md$)|(\/copilot-instructions\.md$)|(\/\.cursor\/rules\/)/i or
      (filepath matches /\.(json|jsonc)$/i and $desc)
    ) and
    (
      any of ($lre, $rle, $lro, $rlo) or
      // Each exempt flag holds exactly six tag characters. More tags than that
      // means at least one tag sits outside a listed flag. No loop, so no bound.
      #tag > 6 * #flag
    )
}
