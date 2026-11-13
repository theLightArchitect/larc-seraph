/*
   SERAPH-YARA-004
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Remote_Npx {
  meta:
    id               = "SERAPH-YARA-004"
    title            = "MCP config runs npx or uvx from a remote or floating tag"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.1.0"
    severity         = "high"
    status           = "experimental"
    score            = "65"
    description      = "Detects an MCP client config that invokes npx, uvx, or npm exec against a URL, a github: specifier, a git+ specifier, or an explicit @latest tag."
    attack_technique = "T1195.002"
    attack_tactic    = "initial-access"
    reference        = "https://attack.mitre.org/techniques/T1195/002/"
    reference_2      = "https://modelcontextprotocol.io/specification/2025-06-18"
    reference_3      = "https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/"
    scope            = "MCP client configs that contain an mcpServers object. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
    false_positives  = "An intentional @latest pin during a review, and any registry package whose name happens to sit within 180 characters of a URL in the same server entry. The stock npx -y scoped package with no tag is not a match."
    license          = "Detection Rule License 1.1"

  strings:
    $mcp      = "\"mcpServers\"" ascii
    $mcp_yaml = /mcpServers[ \t]*:/ ascii
    $mcp_toml = /mcp_servers[ \t]*=/ ascii
    $remote   = /((npx)|(uvx)|(npm[ \t]+exec)).{0,160}(github:|git\+|gist\.github\.com|"https?:\/\/|'https?:\/\/)/s nocase ascii
    $latest   = /((npx)|(uvx)).{0,180}@latest\b/s nocase ascii

  condition:
    (
      (filepath == "" and uint8(0) == 0x7B) or
      (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
        not filepath matches /\.(md|markdown)$/i)
    ) and ($mcp or $mcp_yaml or $mcp_toml) and ($remote or $latest)
}
