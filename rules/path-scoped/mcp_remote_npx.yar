/*
   SERAPH-YARA-004
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Remote_Npx_Path {
  meta:
    id               = "SERAPH-YARA-004-PATH"
    title            = "MCP config runs npx or uvx from a remote or floating tag"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.4.0"
    severity         = "high"
    status           = "experimental"
    score            = 65
    description      = "Detects an MCP client config that invokes npx, uvx, or npm exec against a URL, a github: specifier, a git+ specifier, or a moving dist-tag such as @latest or @next. bunx, pnpm dlx, and yarn dlx count as runners. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1195.002"
    attack_tactic    = "initial-access"
    reference        = "https://attack.mitre.org/techniques/T1195/002/"
    reference        = "https://modelcontextprotocol.io/specification/2025-06-18"
    reference        = "https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/"
    scope            = "MCP client configs: an mcpServers object, Codex mcp_servers tables, a VS Code servers object beside a command key, or Zed context_servers. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
    false_positives  = "An intentional @latest pin during a review, and any registry package whose name happens to sit within 180 characters of a URL in the same server entry. The stock npx -y scoped package with no tag is not a match."
    license          = "Detection Rule License 1.1"

  strings:
    $mcp        = "\"mcpServers\"" ascii
    $mcp_yaml   = /mcpServers[ \t]*:/ ascii
    $mcp_toml   = /mcp_servers[ \t]*=/ ascii
    $mcp_table  = /\[mcp_servers[.\]]/ ascii
    // VS Code writes "servers" and Zed writes "context_servers". "servers" is a
    // common key, so it only counts beside a command key.
    $mcp_vscode = /"servers"[ \t\r\n]*:[ \t\r\n]*\{/ ascii
    $mcp_zed    = "\"context_servers\"" ascii
    $cmd_key    = /(["' \t\n{,]|^)command["']?[ \t]*[:=]/ ascii
    // With no path to consult, the file has to be text (fewer than eight control bytes in
    // the first kilobyte), and the condition accepts a JSON object after an optional
    // BOM and blank space (a leading comment is not accepted, because source files start that way), a top-level mcpServers: key, or an mcp_servers table.
    $yaml_top   = /(^|\n)mcpServers[ \t]*:/ ascii
    $toml_top   = /(^|\n)(\[mcp_servers[.\]]|mcp_servers[ \t]*=)/ ascii
    $remote     = /((npx)|(uvx)|(bunx)|(npm[ \t]+exec)|(pnpm.{0,20}dlx)|(yarn.{0,20}dlx)).{0,160}(github:|gitlab:|bitbucket:|git\+|git@[A-Za-z0-9.-]{1,80}:|git:\/\/|ssh:\/\/|gist\.github\.com|"https?:\/\/|'https?:\/\/)/s nocase ascii
    $latest     = /((npx)|(uvx)|(bunx)|(npm[ \t]+exec)|(pnpm.{0,20}dlx)|(yarn.{0,20}dlx)).{0,180}@(latest|next|beta|canary|dev|nightly)\b/s nocase ascii

  condition:
    (
      (filepath == "" and not for 8 i in (0..1023): (uint8(i) < 9 or (uint8(i) > 13 and uint8(i) < 32 and uint8(i) != 27)) and (for any i in (0..4095): (
            uint8(i) == 0x7B and
            for all j in (0..i): (
              j == i or uint8(j) == 0x20 or uint8(j) == 0x09 or uint8(j) == 0x0A or uint8(j) == 0x0D or
              uint8(j) == 0xEF or uint8(j) == 0xBB or uint8(j) == 0xBF
            )
          ) or $yaml_top or $toml_top)) or
      (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
        not filepath matches /\.(md|markdown)$/i)
    ) and ($mcp or $mcp_yaml or $mcp_toml or $mcp_table or $mcp_zed or ($mcp_vscode and $cmd_key)) and ($remote or $latest)
}
