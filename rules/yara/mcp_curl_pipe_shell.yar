/*
   SERAPH-YARA-002
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Curl_Pipe_Shell
{
    meta:
        id = "SERAPH-YARA-002"
        title = "MCP config pipes a remote fetch into a shell"
        author = "Kevin Francis Tan"
        organization = "Light Architects"
        author_url = "https://lightarchitects.ai"
        date = "2026-11-13"
        modified = "2026-11-13"
        version = "1.0.0"
        severity = "critical"
        description = "An MCP client config contains a fetch utility immediately piped into sh, bash, or zsh, or a process substitution that feeds a fetch into a shell."
        attack_technique = "T1059.004, T1105"
        attack_tactic = "execution, command-and-control"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        reference_2 = "https://attack.mitre.org/techniques/T1105/"
        scope = "MCP client configs that contain an mcpServers object."
        false_positives = "A config that quotes this anti-pattern in a long description field on the same line as a fetch. Review the command and args before deleting a server entry."
        license = "Detection Rule License 1.1"

    strings:
        $mcp = "\"mcpServers\"" ascii
        $pipe_curl = /curl[^\n]{0,200}\|\s*(ba)?sh\b/ nocase ascii
        $pipe_wget = /wget[^\n]{0,200}\|\s*(ba)?sh\b/ nocase ascii
        $pipe_zsh = /(curl|wget)[^\n]{0,200}\|\s*zsh\b/ nocase ascii
        $subst = /(ba)?sh\s+<\s*\(\s*(curl|wget)/ nocase ascii

    condition:
        $mcp and any of ($pipe_curl, $pipe_wget, $pipe_zsh, $subst)
}
