/*
   SERAPH-YARA-009
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SUSP_SERAPH_LaunchPlist_SSH_Reverse_Tunnel {
  meta:
    id               = "SERAPH-YARA-009"
    title            = "LaunchAgent plist opens an SSH reverse tunnel with host-key checking off"
    old_rule_name    = "SERAPH_LaunchPlist_SSH_Reverse_Tunnel"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.1.0"
    severity         = "critical"
    status           = "experimental"
    score            = 75
    description      = "Detects a launchd plist that runs ssh with a reverse forward and StrictHostKeyChecking set to no or off, either as separate argument strings or as one command line."
    attack_technique = "T1572, T1021.004, T1543.001"
    attack_tactic    = "command-and-control, lateral-movement, persistence"
    reference        = "https://attack.mitre.org/techniques/T1572/"
    reference        = "https://attack.mitre.org/techniques/T1021/004/"
    reference        = "https://attack.mitre.org/techniques/T1543/001/"
    scope            = "LaunchAgent and LaunchDaemon plists. A live ssh process is covered by the companion Sigma rule."
    false_positives  = "An administrator who deliberately disables host-key checking on a reverse tunnel and encodes that choice in a plist. accept-new and yes do not match."
    license          = "Detection Rule License 1.1"

  strings:
    $plist   = "<plist" ascii
    $ssh     = /<string>[^<]{0,80}\/(auto)?ssh<\/string>/ ascii
    // -R alone, in a cluster such as -NR, or glued to its value.
    $rev     = /<string>-[A-Za-z]{0,5}R([0-9:\[][^<]{0,80})?<\/string>/ ascii
    // OpenSSH reads off as no.
    $lax     = /<string>[^<]{0,60}StrictHostKeyChecking[= ](no|off)[^<]*<\/string>/ nocase ascii
    $oneline = /ssh[^<\n]{0,160}[ \t]-[A-Za-z]{0,5}R[ \t0-9:\[][^<\n]{0,200}StrictHostKeyChecking[= ](no|off)/ nocase ascii

  condition:
    // A property list opens with its plist element. A transcript that quotes one does not.
    $plist in (0..1024) and (($ssh and $rev and $lax) or $oneline)
}
