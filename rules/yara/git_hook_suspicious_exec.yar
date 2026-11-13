/*
   SERAPH-YARA-010
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SUSP_SERAPH_Git_Hook_Suspicious_Exec {
  meta:
    id               = "SERAPH-YARA-010"
    title            = "Git hook decodes a payload, pipes a fetch into a shell, or posts a credential path"
    old_rule_name    = "SERAPH_Git_Hook_Suspicious_Exec"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.6.0"
    severity         = "high"
    status           = "experimental"
    score            = 45
    description      = "Detects a shell or interpreter script that pipes a fetch into a shell, decodes into a shell, runs a fetch through command substitution, or sends a credential path to a network tool. In a Git hook this is the pattern from the cited incident. This rule has no path, so an installer script with the same line also matches. Treat a match as a lead. Content-only rule: it compiles with no externals."
    attack_technique = "T1059.004, T1546"
    attack_tactic    = "execution, persistence"
    reference        = "https://attack.mitre.org/techniques/T1059/004/"
    reference        = "https://attack.mitre.org/techniques/T1546/"
    reference        = "https://git-scm.com/docs/githooks"
    reference        = "https://opensourcemalware.com/blog/lazarus-group-uses-git-hooks-to-hide-malware"
    scope            = "A shell or interpreter script that pipes a fetch or a decode into a shell, or posts a credential path. Git's sample banner (To enable this hook, rename this file) does not match. A hook that only runs a test suite does not match."
    false_positives  = "A hook that posts a local SSH path to an internal inventory host the operator actually runs. Read the URL. There is no dedicated ATT&CK sub-technique for Git hooks; T1546 is the parent."
    license          = "Detection Rule License 1.1"

  strings:
    // What follows the shell name has to end the command or start an argument,
    // so a Markdown table cell (| zsh |) and a longer word (dash-case) are not a shell.
    $shebang = /^#![ \t]*\/[^\n]{0,120}((\/sh)|(bash)|(zsh)|(dash)|(fish)|(python3?)|(perl)|(ruby)|(node)|(deno)|(bun))\b/ ascii
    $pipe    = /(curl |wget )[^\n]{0,180}\|&?\s*(sudo\s+)?(\/[a-z\/]{1,20}\/)?(ba|z|da|k|fi)?sh(\\?["'`;&)]|[.,:]([ \t\r\n]|$)|[ \t]+[^| \t\r\n]|[ \t]*\r?\n|[ \t]*$)/ nocase ascii
    $b64     = /base64[ \t]+(-[dD]i?|--decode)[^\n]{0,60}\|&?\s*(sudo\s+)?(\/[a-z\/]{1,20}\/)?(ba|z|da|k|fi)?sh(\\?["'`;&)]|[.,:]([ \t\r\n]|$)|[ \t]+[^| \t\r\n]|[ \t]*\r?\n|[ \t]*$)/ nocase ascii
    $cmdsub  = /((ba|z|da|k)?sh\s+-c|eval|source)\s+["']?\$\(\s*(curl|wget)/ nocase ascii
    $net     = /(curl |wget |nc )/ nocase ascii
    $persist = /(\.ssh(\/|\b)|authorized_keys|LaunchAgents\/|LaunchDaemons\/|\.aws\/credentials|\.config\/gh\/)/ ascii

    $sample_banner = /To enable this hook, rename this file/ nocase ascii

  condition:
    not $sample_banner and
    $shebang and ($pipe or $b64 or $cmdsub or ($net and $persist))
}
