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
    version          = "1.5.0"
    severity         = "high"
    status           = "experimental"
    score            = 75
    description      = "Detects a script under .git/hooks, .githooks, or .husky that pipes a fetch into a shell, decodes into a shell, or posts a credential path. Sample hooks are excluded."
    attack_technique = "T1059.004, T1546"
    attack_tactic    = "execution, persistence"
    reference        = "https://attack.mitre.org/techniques/T1059/004/"
    reference        = "https://attack.mitre.org/techniques/T1546/"
    reference        = "https://git-scm.com/docs/githooks"
    reference        = "https://opensourcemalware.com/blog/lazarus-group-uses-git-hooks-to-hide-malware"
    scope            = "Paths under .git/hooks/ or .husky/, any case, excluding names that end in .sample. Set filepath to the path as stored. A hook that only runs a test suite is not a match."
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

  condition:
    not filepath matches /\.sample$/i and
    // .githooks is the usual core.hooksPath name. Husky 9 keeps its hooks one level down, in .husky/_/.
    (filepath matches /\.git\/hooks\/[^\/]+$/i or filepath matches /\.githooks\/[^\/]+$/i or filepath matches /\.husky\/([^\/]+\/)*[^\/]+$/i) and
    $shebang and ($pipe or $b64 or $cmdsub or ($net and $persist))
}
