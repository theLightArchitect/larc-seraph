/*
   SERAPH-YARA-010
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_Git_Hook_Suspicious_Exec {
  meta:
    id               = "SERAPH-YARA-010"
    title            = "Git hook decodes a payload, pipes a fetch into a shell, or posts a credential path"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.4.0"
    severity         = "high"
    status           = "experimental"
    score            = "75"
    description      = "Detects a script under .git/hooks or .husky that pipes a fetch into a shell, decodes into a shell, or posts a credential path. Sample hooks are excluded. Content-only rule: it compiles with no externals."
    attack_technique = "T1059.004, T1546"
    attack_tactic    = "execution, persistence"
    reference        = "https://attack.mitre.org/techniques/T1059/004/"
    reference_2      = "https://attack.mitre.org/techniques/T1546/"
    reference_3      = "https://git-scm.com/docs/githooks"
    reference_4      = "https://opensourcemalware.com/blog/lazarus-group-uses-git-hooks-to-hide-malware"
    scope            = "A shell or interpreter script that pipes a fetch or a decode into a shell, or posts a credential path. Git's sample banner (To enable this hook, rename this file) does not match. A hook that only runs a test suite does not match."
    false_positives  = "A hook that posts a local SSH path to an internal inventory host the operator actually runs. Read the URL. There is no dedicated ATT&CK sub-technique for Git hooks; T1546 is the parent."
    license          = "Detection Rule License 1.1"

  strings:
    $shebang  = /^#!\/[^\n]{0,120}((\/sh)|(bash)|(zsh)|(python3?)|(perl)|(ruby))\b/ ascii
    $pipe     = /(curl |wget )[^\n]{0,180}\|\s*(ba)?sh\b/ nocase ascii
    $pipe_zsh = /(curl |wget )[^\n]{0,180}\|\s*zsh\b/ nocase ascii
    $b64      = /base64[ \t]+(-[dD]|--decode)[^\n]{0,60}\|\s*(ba)?sh\b/ nocase ascii
    $net      = /(curl |wget |nc )/ nocase ascii
    $persist  = /(\.ssh\/|authorized_keys|LaunchAgents\/|LaunchDaemons\/)/ ascii

    $sample_banner = /To enable this hook, rename this file/ nocase ascii

  condition:
    not $sample_banner and
    $shebang and ($pipe or $pipe_zsh or $b64 or ($net and $persist))
}
