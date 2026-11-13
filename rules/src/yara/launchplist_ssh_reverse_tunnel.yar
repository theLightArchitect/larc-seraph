/*
   SERAPH-YARA-009
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_LaunchPlist_SSH_Reverse_Tunnel {
  meta:
    id               = "SERAPH-YARA-009"
    title            = "LaunchAgent plist opens an SSH reverse tunnel with host-key checking off"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.0.0"
    severity         = "critical"
    status           = "experimental"
    score            = "75"
    description      = "Detects a launchd plist that runs ssh with a reverse forward and StrictHostKeyChecking set to no, either as separate argument strings or as one command line."
    attack_technique = "T1572, T1021.004, T1543.001"
    attack_tactic    = "command-and-control, lateral-movement, persistence"
    reference        = "https://attack.mitre.org/techniques/T1572/"
    reference_2      = "https://attack.mitre.org/techniques/T1021/004/"
    reference_3      = "https://attack.mitre.org/techniques/T1543/001/"
    scope            = "LaunchAgent and LaunchDaemon plists. A live ssh process is covered by the companion Sigma rule."
    false_positives  = "An administrator who deliberately disables host-key checking on a reverse tunnel and encodes that choice in a plist. accept-new and yes do not match."
    license          = "Detection Rule License 1.1"

  strings:
    $plist   = "<plist" ascii
    $ssh     = /<string>[^<]{0,80}\/ssh<\/string>/ ascii
    $rev     = "<string>-R</string>" ascii
    $lax     = /<string>[^<]{0,60}StrictHostKeyChecking=no[^<]*<\/string>/ nocase ascii
    $oneline = /ssh[^<\n]{0,160}-R[^<\n]{0,200}StrictHostKeyChecking=no/ nocase ascii

  condition:
    $plist and (($ssh and $rev and $lax) or $oneline)
}
