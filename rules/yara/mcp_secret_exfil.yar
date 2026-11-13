/*
   SERAPH-YARA-005
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Secret_Exfil
{
    meta:
        id = "SERAPH-YARA-005"
        title = "MCP config places a secret environment variable on a network sink"
        author = "Kevin Francis Tan"
        organization = "Light Architects"
        author_url = "https://lightarchitects.ai"
        date = "2026-11-13"
        modified = "2026-11-13"
        version = "1.0.0"
        severity = "critical"
        description = "An MCP client config interpolates a well-known API token variable into a URL or a curl or wget invocation, or pipes printenv into a fetch utility."
        attack_technique = "T1552.001, T1567"
        attack_tactic = "credential-access, exfiltration"
        reference = "https://attack.mitre.org/techniques/T1567/"
        reference_2 = "https://attack.mitre.org/techniques/T1552/001/"
        scope = "MCP client configs that contain an mcpServers object. Presence of a token variable in an env map is not enough."
        false_positives = "A local proxy command that forwards one named token to its own vendor host. Read the destination host before treating the match as theft."
        license = "Detection Rule License 1.1"

    strings:
        $mcp = "\"mcpServers\"" ascii
        $mcp_yaml = /mcpServers[ \t]*:/ ascii
        $mcp_toml = /mcp_servers[ \t]*=/ ascii
        $curl = /curl [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b/ nocase ascii
        $wget = /wget [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b/ nocase ascii
        $url = /https?:\/\/[^\s"']{0,180}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b/ nocase ascii
        $printenv = /printenv[^\n]{0,80}\|[^\n]{0,40}(curl |wget )/ nocase ascii

    condition:
        (
            (filepath == "" and uint8(0) == 0x7B) or
            (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)$/)
        ) and ($mcp or $mcp_yaml or $mcp_toml) and any of ($curl, $wget, $url, $printenv)
}
