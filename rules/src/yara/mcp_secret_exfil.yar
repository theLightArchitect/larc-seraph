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
        version = "1.2.0"
        severity = "critical"
        description = "An MCP client config sends a well-known API token to a host that is not that token's vendor, or pipes printenv into a fetch utility. A token used against its own vendor API does not match."
        attack_technique = "T1552.001, T1567"
        attack_tactic = "credential-access, exfiltration"
        reference = "https://attack.mitre.org/techniques/T1567/"
        reference_2 = "https://attack.mitre.org/techniques/T1552/001/"
        scope = "MCP client configs that contain an mcpServers object. Presence of a token variable in an env map is not enough. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
        false_positives = "A command that posts one named token to a lookalike host. A file that contains both an official vendor call and a cross-host call still matches on the cross-host call when the two do not overlap."
        license = "Detection Rule License 1.1"

    strings:
        $mcp = "\"mcpServers\"" ascii
        $mcp_yaml = /mcpServers[ \t]*:/ ascii
        $mcp_toml = /mcp_servers[ \t]*=/ ascii
        $curl = /curl [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b/ nocase ascii
        $wget = /wget [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b/ nocase ascii
        $url = /https?:\/\/[^\s"']{0,180}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b/ nocase ascii
        $printenv = /printenv[^\n]{0,80}\|[^\n]{0,40}(curl |wget )/ nocase ascii
        // Token plus its own vendor host, either order, on one line.
        $official = /https?:\/\/([A-Za-z0-9-]+\.)*github\.com\b[^\n]{0,220}\$\{?(GITHUB_TOKEN|GH_TOKEN)\b|\$\{?(GITHUB_TOKEN|GH_TOKEN)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*github\.com\b|https?:\/\/([A-Za-z0-9-]+\.)*openai\.com\b[^\n]{0,220}\$\{?OPENAI_API_KEY\b|\$\{?OPENAI_API_KEY\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*openai\.com\b|https?:\/\/([A-Za-z0-9-]+\.)*anthropic\.com\b[^\n]{0,220}\$\{?ANTHROPIC_API_KEY\b|\$\{?ANTHROPIC_API_KEY\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*anthropic\.com\b|https?:\/\/([A-Za-z0-9-]+\.)*amazonaws\.com\b[^\n]{0,220}\$\{?(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b|\$\{?(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*amazonaws\.com\b/ nocase ascii

    condition:
        (
            (filepath == "" and uint8(0) == 0x7B) or
            (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
                not filepath matches /\.(md|markdown)$/i)
        ) and ($mcp or $mcp_yaml or $mcp_toml) and (
            $printenv or
            for any i in (1..8) : (
                (
                    i <= #curl and
                    not for any k in (1..6) : (
                        k <= #official and
                        @official[k] < @curl[i] + !curl[i] and
                        @official[k] + !official[k] > @curl[i]
                    )
                ) or (
                    i <= #wget and
                    not for any k in (1..6) : (
                        k <= #official and
                        @official[k] < @wget[i] + !wget[i] and
                        @official[k] + !official[k] > @wget[i]
                    )
                ) or (
                    i <= #url and
                    not for any k in (1..6) : (
                        k <= #official and
                        @official[k] < @url[i] + !url[i] and
                        @official[k] + !official[k] > @url[i]
                    )
                )
            )
        )
}
