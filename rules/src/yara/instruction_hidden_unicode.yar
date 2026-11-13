/*
   SERAPH-YARA-006
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.

   Scanners must pass the external string filepath with forward slashes.
   An empty filepath does not match this rule.
*/

import "math"

rule SERAPH_Instruction_Hidden_Unicode {
  meta:
    id               = "SERAPH-YARA-006"
    title            = "Instruction file contains Unicode tags or bidi overrides"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.3.0"
    severity         = "high"
    status           = "experimental"
    score            = "80"
    description      = "Detects Unicode tag characters or a bidi override in an instruction file. Subdivision-flag emoji (U+1F3F4 plus tags plus U+E007F) are ignored. Binaries are ignored."
    attack_technique = "T1027"
    attack_tactic    = "defense-evasion"
    reference        = "https://attack.mitre.org/techniques/T1027/"
    reference_2      = "https://www.unicode.org/charts/PDF/UE0000.pdf"
    reference_3      = "https://www.usenix.org/conference/usenixsecurity22/presentation/boucher"
    reference_4      = "https://atlas.mitre.org/techniques/AML.T0051"
    reference_5      = "https://securityaffairs.com/175593/hacking/rules-file-backdoor-ai-code-editors-silent-supply-chain-attacks.html"
    reference_6      = "https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"
    scope            = "AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .cursor/rules/*, SKILL.md, copilot-instructions.md, and JSON MCP configs, any case. Set filepath to the path as stored. Binaries and subdivision flags are skipped."
    false_positives  = "An instruction file that embeds the raw controls on purpose. larc-seraph docs name the code points and do not embed them."
    license          = "Detection Rule License 1.1"

  strings:
    // UTF-8 for U+E0000..U+E007F. Hex atoms stay inside the fast path.
    $tag  = { F3 A0 (80 | 81) ?? }
    $desc = "\"description\"" ascii
    // Trojan Source controls: LRE U+202A, RLE U+202B, LRO U+202D, RLO U+202E.
    $lre  = { E2 80 AA }
    $rle  = { E2 80 AB }
    $lro  = { E2 80 AD }
    $rlo  = { E2 80 AE }

  condition:
    filesize > 0 and filesize < 5000000 and
    not (uint32(0) == 0x464c457f) and
    not (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcffaedfe or uint32(0) == 0xbebafeca) and
    not (uint16(0) == 0x5a4d) and
    not (uint32(0) == 0x04034b50) and
    not (uint16(0) == 0x8b1f) and
    not for any i in (0..math.min(1023, filesize - 1)): (uint8(i) == 0) and
    (
      filepath matches /(\/(agents|claude|gemini)\.md$)|(\/\.cursorrules$)|(\/skill\.md$)|(\/copilot-instructions\.md$)|(\/\.cursor\/rules\/)/i or
      (filepath matches /\.(json|jsonc)$/i and $desc)
    ) and
    (
      any of ($lre, $rle, $lro, $rlo) or
      for any i in (1..32): (
        i <= #tag and
        not (
          for any d in (0..12): (
            @tag[i] >= 4 * (d + 1) and
            uint32(@tag[i] - 4 * (d + 1)) == 0xB48F9FF0 and
            for all k in (0..d): (
              uint8(@tag[i] - 4 * k) == 0xF3 and
              uint8(@tag[i] - 4 * k + 1) == 0xA0 and
              (uint8(@tag[i] - 4 * k + 2) == 0x80 or uint8(@tag[i] - 4 * k + 2) == 0x81)
            )
          )
        )
      )
    )
}
