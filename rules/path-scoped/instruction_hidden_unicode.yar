/*
   SERAPH-YARA-006
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.

   Scanners must pass the external string filepath with forward slashes.
   An empty filepath does not match this rule.
*/

rule SUSP_SERAPH_Instruction_Hidden_Unicode_Path {
  meta:
    id               = "SERAPH-YARA-006-PATH"
    title            = "Instruction file contains Unicode tags or bidi overrides"
    old_rule_name    = "SERAPH_Instruction_Hidden_Unicode_Path"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.7.0"
    severity         = "high"
    status           = "experimental"
    score            = 80
    description      = "Detects Unicode tag characters, a bidi override or isolate, or a run of variation selectors in an instruction file. The three subdivision flags Unicode recommends (England, Scotland, Wales) are ignored. Every tag character is checked, however many flags come first. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1027"
    attack_tactic    = "defense-evasion"
    reference        = "https://attack.mitre.org/techniques/T1027/"
    reference        = "https://www.unicode.org/charts/PDF/UE0000.pdf"
    reference        = "https://www.usenix.org/conference/usenixsecurity23/presentation/boucher"
    reference        = "https://atlas.mitre.org/techniques/AML.T0051"
    reference        = "https://securityaffairs.com/175593/hacking/rules-file-backdoor-ai-code-editors-silent-supply-chain-attacks.html"
    reference        = "https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"
    scope            = "AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .cursor/rules/*, SKILL.md, copilot-instructions.md, and JSON MCP configs, any case. Set filepath to the path as stored. The England, Scotland, and Wales flag sequences are skipped. Zero-width characters and a single variation selector are not in this rule."
    false_positives  = "An instruction file that embeds the raw controls on purpose. larc-seraph docs name the code points and do not embed them. Right-to-left text that an editor wrapped in bidi embeddings or isolates also matches."
    license          = "Detection Rule License 1.1"

  strings:
    // UTF-8 for U+E0000..U+E007F. Hex atoms stay inside the fast path.
    $tag     = { F3 A0 (80 | 81) ?? }
    // U+1F3F4, tag g, tag b, then eng, sct, or wls, then the cancel tag U+E007F.
    // These three are the only subdivision flags in Unicode's RGI emoji set.
    // A black flag followed by any other tag run is not exempt.
    $flag    = { F0 9F 8F B4 F3 A0 81 A7 F3 A0 81 A2 (F3 A0 81 A5 F3 A0 81 AE F3 A0 81 A7 | F3 A0 81 B3 F3 A0 81 A3 F3 A0 81 B4 | F3 A0 81 B7 F3 A0 81 AC F3 A0 81 B3) F3 A0 81 BF }
    $desc    = "\"description\"" ascii
    // A JSON file is a tool list only when it also has one of these keys.
    $toolkey = /"(tools|inputSchema|input_schema|mcpServers|context_servers)"/ ascii
    // Trojan Source controls: LRE U+202A, RLE U+202B, LRO U+202D, RLO U+202E.
    $lre     = { E2 80 AA }
    $rle     = { E2 80 AB }
    $lro     = { E2 80 AD }
    $rlo     = { E2 80 AE }
    // Trojan Source isolates: LRI U+2066, RLI U+2067, FSI U+2068.
    $lri     = { E2 81 A6 }
    $rli     = { E2 81 A7 }
    $fsi     = { E2 81 A8 }
    // Two variation selectors from the supplement (U+E0100 to U+E01EF) in a row, or
    // three from the basic block (U+FE00 to U+FE0F). One after a base character is
    // ordinary. A run is how bytes are smuggled.
    $vs_run  = { F3 A0 (84 | 85 | 86 | 87) ?? F3 A0 (84 | 85 | 86 | 87) ?? }
    $vs_bmp  = { EF B8 8? EF B8 8? EF B8 8? }

  condition:
    filesize > 0 and filesize < 5000000 and
    (
      filepath matches /(\/(agents|claude|gemini)\.md$)|(\/\.cursorrules$)|(\/skill\.md$)|(\/copilot-instructions\.md$)|(\/\.cursor\/rules\/)/i or
      (filepath matches /\.(json|jsonc)$/i and $desc and $toolkey)
    ) and
    (
      any of ($lre, $rle, $lro, $rlo, $lri, $rli, $fsi) or $vs_run or $vs_bmp or
      // Each exempt flag holds exactly six tag characters. More tags than that
      // means at least one tag sits outside a listed flag. No loop, so no bound.
      #tag > 6 * #flag
    )
}
