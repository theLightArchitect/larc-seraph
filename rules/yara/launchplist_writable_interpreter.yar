/*
   SERAPH-YARA-008
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SUSP_SERAPH_LaunchPlist_Writable_Interpreter {
  meta:
    id               = "SERAPH-YARA-008"
    title            = "LaunchAgent plist runs a shell from a user-writable path"
    old_rule_name    = "SERAPH_LaunchPlist_Writable_Interpreter"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.3.0"
    severity         = "high"
    status           = "experimental"
    score            = 70
    description      = "Detects a launchd plist, XML, UTF-16 XML, or binary, that sets RunAtLoad and KeepAlive, names a shell or interpreter, and passes a path under /Users, /tmp, /var/folders, /var/tmp, or /dev/shm."
    attack_technique = "T1543.001, T1543.004, T1059.004"
    attack_tactic    = "persistence, execution"
    reference        = "https://attack.mitre.org/techniques/T1543/001/"
    reference        = "https://attack.mitre.org/techniques/T1543/004/"
    reference        = "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html"
    reference        = "https://www.broadcom.com/support/security-center/protection-bulletin/amos-atomic-macos-stealer-malware-deployed-in-latest-clickfix-campaign-targeting-macos-users"
    scope            = "LaunchAgent and LaunchDaemon plists. The same content shape covers both. KeepAlive may be a boolean or a dictionary."
    false_positives  = "A developer LaunchAgent that reloads a personal script from the home directory on login. Homebrew prefixes and /usr/local are not in the writable set, so those jobs are not matched."
    license          = "Detection Rule License 1.1"

  strings:
    // wide covers a UTF-16LE plist. The marker may sit past a BOM and doubled bytes.
    $plist     = "<plist" ascii
    $plist_w   = "<plist" wide
    // A comment between a key and its value does not change what the parser reads.
    $run       = /<key>RunAtLoad<\/key>(\s|<!--[^>]{0,80}-->)*<true\s*\/>/ ascii wide
    $keep_bool = /<key>KeepAlive<\/key>(\s|<!--[^>]{0,80}-->)*<(true\s*\/|integer>[1-9][0-9]{0,8}<\/integer)>/ ascii wide
    $keep_dict = /<key>KeepAlive<\/key>(\s|<!--[^>]{0,80}-->)*<dict>/ ascii wide
    // A slash may arrive as a numeric character reference. A parser decodes it, so the rule does too.
    $interp    = /<string>(\/|&#0*47;|&#[xX]0*2[fF];)(bin(\/|&#0*47;|&#[xX]0*2[fF];)(bash|sh|zsh|dash)|usr(\/|&#0*47;|&#[xX]0*2[fF];)bin(\/|&#0*47;|&#[xX]0*2[fF];)(env|python3?|osascript|perl|ruby)|usr(\/|&#0*47;|&#[xX]0*2[fF];)local(\/|&#0*47;|&#[xX]0*2[fF];)bin(\/|&#0*47;|&#[xX]0*2[fF];)(python3?|node)|opt(\/|&#0*47;|&#[xX]0*2[fF];)homebrew(\/|&#0*47;|&#[xX]0*2[fF];)bin(\/|&#0*47;|&#[xX]0*2[fF];)(python3?|node))<\/string>/ ascii wide
    $user      = /<string>[^<]{0,220}(\/|&#0*47;|&#[xX]0*2[fF];)(Users|tmp|private(\/|&#0*47;|&#[xX]0*2[fF];)tmp|var(\/|&#0*47;|&#[xX]0*2[fF];)folders|var(\/|&#0*47;|&#[xX]0*2[fF];)tmp|dev(\/|&#0*47;|&#[xX]0*2[fF];)shm)(\/|&#0*47;|&#[xX]0*2[fF];)/ ascii wide
    // Binary plist. Strings carry a length marker, so each name below is the whole string.
    $b_magic   = "bplist00" ascii
    $b_run     = "YRunAtLoad" ascii
    $b_keep    = "YKeepAlive" ascii
    $b_interp  = /(\x59\/bin\/bash|\x57\/bin\/sh|\x58\/bin\/zsh|\x59\/bin\/dash|\x5c\/usr\/bin\/env|\x5f\x10\x19\/opt\/homebrew\/bin\/python3|\x5f\x10\x18\/opt\/homebrew\/bin\/python|\x5f\x10\x16\/usr\/local\/bin\/python3|\x5f\x10\x15\/usr\/local\/bin\/python|\x5f\x10\x10\/usr\/bin\/python3|\x5f\x10\x0f\/usr\/bin\/python|\x5f\x10\x12\/usr\/bin\/osascript|\x5d\/usr\/bin\/perl|\x5d\/usr\/bin\/ruby|\x5f\x10\x13\/usr\/local\/bin\/node|\x5f\x10\x16\/opt\/homebrew\/bin\/node)/ ascii
    $b_user    = /(\/Users\/|\/tmp\/|\/private\/tmp\/|\/var\/folders\/|\/var\/tmp\/|\/dev\/shm\/)/ ascii

  condition:
    (
      ($plist in (0..1024) or $plist_w in (0..2048)) and $run and ($keep_bool or $keep_dict) and $interp and $user
    ) or (
      $b_magic at 0 and $b_run and $b_keep and $b_interp and $b_user
    )
}
