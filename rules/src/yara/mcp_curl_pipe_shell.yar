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
        version = "1.1.0"
        severity = "critical"
        description = "An MCP client config contains a fetch utility immediately piped into sh, bash, or zsh, or a process substitution that feeds a fetch into a shell."
        attack_technique = "T1059.004, T1105"
        attack_tactic = "execution, command-and-control"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        reference_2 = "https://attack.mitre.org/techniques/T1105/"
        scope = "MCP client configs that contain an mcpServers object. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
        false_positives = "A config that quotes this anti-pattern in a long description field on the same line as a fetch. Review the command and args before deleting a server entry."
        license = "Detection Rule License 1.1"

    strings:
        $mcp = "\"mcpServers\"" ascii
        $mcp_yaml = /mcpServers[ \t]*:/ ascii
        $mcp_toml = /mcp_servers[ \t]*=/ ascii
        $pipe_curl = /curl[^\n]{0,200}\|\s*(ba)?sh\b/ nocase ascii
        $pipe_wget = /wget[^\n]{0,200}\|\s*(ba)?sh\b/ nocase ascii
        $pipe_zsh = /(curl|wget)[^\n]{0,200}\|\s*zsh\b/ nocase ascii
        $subst = /(ba)?sh\s+<\s*\(\s*(curl|wget)/ nocase ascii

    condition:
        (
            (filepath == "" and uint8(0) == 0x7B) or
            (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
                not filepath matches /\.(md|markdown)$/i)
        ) and ($mcp or $mcp_yaml or $mcp_toml) and any of ($pipe_curl, $pipe_wget, $pipe_zsh, $subst)
}
