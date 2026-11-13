/*
   SERAPH-YARA-016
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Unpinned_Package
{
    meta:
        id = "SERAPH-YARA-016"
        title = "MCP config runs an unpinned npx or uvx package"
        author = "Kevin Francis Tan"
        organization = "Light Architects"
        author_url = "https://lightarchitects.ai"
        date = "2026-11-13"
        modified = "2026-11-13"
        version = "1.0.0"
        severity = "medium"
        description = "An MCP client config starts npx or uvx with a package that has no numeric version and is not an allowlisted first-party scope. Remote URLs and explicit @latest tags are SERAPH-YARA-004."
        attack_technique = "T1195.002"
        attack_tactic = "initial-access"
        reference = "https://attack.mitre.org/techniques/T1195/002/"
        reference_2 = "https://modelcontextprotocol.io/specification/2025-06-18"
        scope = "MCP client configs that contain an mcpServers object. Allowlisted scopes are @modelcontextprotocol, @anthropic, and @github."
        false_positives = "A community MCP server installed the way its README shows, with npx -y and no version. The allowlist is short on purpose. Review the package name."
        license = "Detection Rule License 1.1"

    strings:
        $mcp = "\"mcpServers\"" ascii
        $runner = /"command"\s*:\s*"(npx|uvx)"/ nocase ascii
        // Bare package: " -y ", "name" with no @ and no slash.
        $bare_y = /"(-y|--yes)"\s*,\s*"[A-Za-z0-9][A-Za-z0-9._-]*"/ ascii
        // Scoped package with no version suffix: "@scope/name"
        $scoped = /"(-y|--yes)"\s*,\s*"@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+"/ ascii
        // uvx often omits -y: the first args element is the package name.
        $uvx_bare = /"command"\s*:\s*"uvx"[\s\S]{0,80}"args"\s*:\s*\[\s*"[A-Za-z0-9][A-Za-z0-9._-]*"/ ascii
        $pinned = /@[0-9][0-9A-Za-z._-]*/ ascii
        $official_mcp = /"@modelcontextprotocol\/[A-Za-z0-9._-]+"/ ascii
        $official_anthropic = /"@anthropic\/[A-Za-z0-9._-]+"/ ascii
        $official_github = /"@github\/[A-Za-z0-9._-]+"/ ascii

    condition:
        $mcp and $runner and not $pinned and not $official_mcp and not $official_anthropic and not $official_github and (
            $bare_y or $scoped or $uvx_bare
        )
}
