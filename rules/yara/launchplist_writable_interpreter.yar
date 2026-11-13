/*
   SERAPH-YARA-008
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_LaunchPlist_Writable_Interpreter
{
    meta:
        id = "SERAPH-YARA-008"
        title = "LaunchAgent plist runs a shell from a user-writable path"
        author = "Kevin Francis Tan"
        organization = "Light Architects"
        author_url = "https://lightarchitects.ai"
        date = "2026-11-13"
        modified = "2026-11-13"
        version = "1.1.0"
        severity = "high"
        description = "A launchd plist sets RunAtLoad and KeepAlive, either as a boolean or a dictionary, names a shell or interpreter, and passes a path under /Users, /tmp, /var/folders, /var/tmp, or /dev/shm."
        attack_technique = "T1543.001, T1543.004, T1059.004"
        attack_tactic = "persistence, execution"
        reference = "https://attack.mitre.org/techniques/T1543/001/"
        reference_2 = "https://attack.mitre.org/techniques/T1543/004/"
        reference_3 = "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html"
        scope = "LaunchAgent and LaunchDaemon plists. The same content shape covers both. KeepAlive may be a boolean or a dictionary."
        false_positives = "A developer LaunchAgent that reloads a personal script from the home directory on login. Homebrew prefixes and /usr/local are not in the writable set, so those jobs are not matched."
        license = "Detection Rule License 1.1"

    strings:
        $plist = "<plist" ascii
        $run = /<key>RunAtLoad<\/key>\s*<true\s*\/>/ ascii
        $keep_bool = /<key>KeepAlive<\/key>\s*<true\s*\/>/ ascii
        $keep_dict = /<key>KeepAlive<\/key>\s*<dict>/ ascii
        $interp = /<string>\/(bin\/bash|bin\/sh|bin\/zsh|usr\/bin\/python3?|usr\/bin\/osascript|usr\/bin\/perl|usr\/bin\/ruby|usr\/local\/bin\/node|opt\/homebrew\/bin\/node)<\/string>/ ascii
        $user = /<string>[^<]{0,220}(\/Users\/|\/tmp\/|\/private\/tmp\/|\/var\/folders\/|\/var\/tmp\/|\/dev\/shm\/)/ ascii

    condition:
        $plist and $run and ($keep_bool or $keep_dict) and $interp and $user
}
