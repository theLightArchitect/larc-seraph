/*
   SERAPH-YARA-006
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.

*/

rule SUSP_SERAPH_Instruction_Hidden_Unicode {
  meta:
    id               = "SERAPH-YARA-006"
    title            = "Instruction file contains Unicode tags or bidi overrides"
    old_rule_name    = "SERAPH_Instruction_Hidden_Unicode"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.9.0"
    severity         = "high"
    status           = "experimental"
    score            = 50
    description      = "Detects Unicode tag characters, a bidi override or isolate, or a run of variation selectors in a text file. This rule has no path, so ordinary right-to-left text that uses an embedding mark also matches. The England, Scotland, and Wales flag emoji are ignored. Content-only rule: it compiles with no externals."
    attack_technique = "T1027"
    attack_tactic    = "defense-evasion"
    reference        = "https://attack.mitre.org/techniques/T1027/"
    reference        = "https://www.unicode.org/charts/PDF/UE0000.pdf"
    reference        = "https://www.usenix.org/conference/usenixsecurity23/presentation/boucher"
    reference        = "https://atlas.mitre.org/techniques/AML.T0051"
    reference        = "https://securityaffairs.com/175593/hacking/rules-file-backdoor-ai-code-editors-silent-supply-chain-attacks.html"
    reference        = "https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"
    scope            = "Text with a Unicode tag or a bidi override (LRE, RLE, LRO, RLO). The portable rule does not require the file to mention its own name, because a real CLAUDE.md or .cursor/rules file often does not. The England, Scotland, and Wales flag emoji do not match. A file whose first kilobyte holds eight or more control bytes is treated as binary and skipped."
    false_positives  = "An instruction file that embeds the raw controls on purpose. larc-seraph docs name the code points and do not embed them. Right-to-left text that an editor wrapped in bidi embeddings or isolates also matches."
    license          = "Detection Rule License 1.1"

  strings:
    // UTF-8 for U+E0000..U+E007F. Hex atoms stay inside the fast path.
    $tag     = { F3 A0 (80 | 81) ?? }
    // U+1F3F4, tag g, tag b, then eng, sct, or wls, then the cancel tag U+E007F.
    // These three are the only subdivision flags in Unicode's RGI emoji set.
    // A black flag followed by any other tag run is not exempt.
    $flag    = { F0 9F 8F B4 F3 A0 81 A7 F3 A0 81 A2 (F3 A0 81 A5 F3 A0 81 AE F3 A0 81 A7 | F3 A0 81 B3 F3 A0 81 A3 F3 A0 81 B4 | F3 A0 81 B7 F3 A0 81 AC F3 A0 81 B3) F3 A0 81 BF }
    // The same tag characters in UTF-16 text that starts with a byte order mark. A tag
    // character is the surrogate pair U+DB40 then U+DC00..U+DC7F. Only a file with a
    // byte order mark is read this way, because it is the BOM that says the bytes are
    // 16-bit units and not binary.
    $tag_le  = { 40 DB (0? | 1? | 2? | 3? | 4? | 5? | 6? | 7?) DC }
    $tag_be  = { DB 40 DC (0? | 1? | 2? | 3? | 4? | 5? | 6? | 7?) }
    $flag_le = { 3C D8 F4 DF 40 DB 67 DC 40 DB 62 DC (40 DB 65 DC 40 DB 6E DC 40 DB 67 DC | 40 DB 73 DC 40 DB 63 DC 40 DB 74 DC | 40 DB 77 DC 40 DB 6C DC 40 DB 73 DC) 40 DB 7F DC }
    $flag_be = { D8 3C DF F4 DB 40 DC 67 DB 40 DC 62 (DB 40 DC 65 DB 40 DC 6E DB 40 DC 67 | DB 40 DC 73 DB 40 DC 63 DB 40 DC 74 | DB 40 DC 77 DB 40 DC 6C DB 40 DC 73) DB 40 DC 7F }
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
    // Eight zero-width space, non-joiner, or joiner characters in a row. One of
    // them is common. A run is how bits are smuggled.
    $zw_run  = { E2 80 (8B | 8C | 8D) E2 80 (8B | 8C | 8D) E2 80 (8B | 8C | 8D) E2 80 (8B | 8C | 8D) E2 80 (8B | 8C | 8D) E2 80 (8B | 8C | 8D) E2 80 (8B | 8C | 8D) E2 80 (8B | 8C | 8D) }

  condition:
    filesize > 0 and filesize < 5000000 and
    (
      (
        not for 8 i in (0..1023): (i < filesize and (uint8(i) < 9 or (uint8(i) > 13 and uint8(i) < 32 and uint8(i) != 27))) and
        (
          any of ($lre, $rle, $lro, $rlo, $lri, $rli, $fsi) or $vs_run or $vs_bmp or $zw_run or
          // Each exempt flag holds exactly six tag characters. More tags than that
          // means at least one tag sits outside a listed flag. No loop, so no bound.
          #tag > 6 * #flag
        )
      ) or
      (uint16(0) == 0xFEFF and #tag_le > 6 * #flag_le) or
      (uint16(0) == 0xFFFE and #tag_be > 6 * #flag_be)
    )
}
