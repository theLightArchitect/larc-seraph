/*
   SERAPH-YARA-007
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.

   English confirmation-bypass paraphrases are evaluated by larc_seraph.phrases.
   This rule is the high-precision core a YARA-only scanner can compile.
*/

import "math"

rule SERAPH_Instruction_Unsafe_Directive_Path {
  meta:
    id               = "SERAPH-YARA-007-PATH"
    title            = "Agent instructions request secret theft or skipped confirmation"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.9.0"
    severity         = "high"
    status           = "experimental"
    score            = "70"
    description      = "Detects a Cyrillic homoglyph of do-not-ask, a credential path next to curl or wget, or ignore-previous-instructions next to a fetch. English paraphrases are matched by the larc-seraph scanner in larc_seraph.phrases, not by this rule, so a YARA-only copy misses those sentences. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1567, T1562.001"
    attack_tactic    = "exfiltration, defense-evasion"
    reference        = "https://attack.mitre.org/techniques/T1567/"
    reference_2      = "https://attack.mitre.org/techniques/T1562/001/"
    reference_3      = "https://securityaffairs.com/175593/hacking/rules-file-backdoor-ai-code-editors-silent-supply-chain-attacks.html"
    reference_4      = "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
    scope            = "AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .cursor/rules/*, SKILL.md, copilot-instructions.md, and JSON tool descriptions, any case. The YARA core does not parse English confirmation-bypass sentences."
    false_positives  = "A credential file and a fetch in the same short span that is a real operator example. Homoglyphs other than Cyrillic o are not in this core."
    license          = "Detection Rule License 1.1"

  strings:
    $desc            = "\"description\"" ascii
    $homo            = { 64 D0 BE 20 6E D0 BE 74 20 61 73 6B 20 66 D0 BE 72 20 63 D0 BE 6E 66 69 72 6D 61 74 69 D0 BE 6E }
    $file_then_fetch = /(\.ssh\/authorized_keys|\.aws\/credentials|id_ed25519|id_rsa|\.netrc)[^\n]{0,320}(curl |wget )/ nocase ascii
    $fetch_then_file = /(curl |wget )[^\n]{0,320}(\.ssh\/authorized_keys|\.aws\/credentials|id_ed25519|id_rsa|\.netrc)/ nocase ascii
    $inject_fwd      = /ignore (all )?(previous|prior|above) instructions[^\n]{0,400}(curl |wget |https?:\/\/)/ nocase ascii
    $inject_rev      = /(curl |wget |https?:\/\/)[^\n]{0,400}ignore (all )?(previous|prior|above) instructions/ nocase ascii

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
    ($homo or $file_then_fetch or $fetch_then_file or $inject_fwd or $inject_rev)
}
