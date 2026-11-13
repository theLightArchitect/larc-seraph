/*
   SERAPH-YARA-016
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Unpinned_Package {
  meta:
    id               = "SERAPH-YARA-016"
    title            = "MCP config runs an unpinned npx or uvx package"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.2.0"
    severity         = "medium"
    status           = "experimental"
    score            = "55"
    description      = "Detects an MCP client config that starts npx or uvx with a package that has no numeric version and is not an allowlisted first-party scope. Remote URLs and explicit @latest tags are SERAPH-YARA-004. A pin or an allowlisted package elsewhere in the file does not clear a second unpinned package."
    attack_technique = "T1195.002"
    attack_tactic    = "initial-access"
    reference        = "https://attack.mitre.org/techniques/T1195/002/"
    reference_2      = "https://modelcontextprotocol.io/specification/2025-06-18"
    reference_3      = "https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/"
    scope            = "JSON, TOML, or YAML MCP configs. Markdown docs do not match. Allowlisted scopes are @modelcontextprotocol, @anthropic, and @github. A package token that itself contains @ and a version does not match. @latest is SERAPH-YARA-004."
    false_positives  = "A community MCP server installed the way its README shows, with npx and no version. The allowlist is short on purpose. Review the package name."
    license          = "Detection Rule License 1.1"

  strings:
    $mcp_json       = /['"]mcpServers['"][ \t]*:/ ascii
    $mcp_yaml       = /mcpServers[ \t]*:/ ascii
    $mcp_toml       = /mcp_servers[ \t]*=/ ascii
    $mcp_toml_table = /\[mcp_servers/ ascii
    $start_yaml     = /^mcpServers[ \t]*:/ ascii
    $start_toml     = /^(\[mcp_servers|mcp_servers[ \t]*=)/ ascii
    $cmd_json       = /['"]command['"][ \t]*:[ \t]*['"](npx|uvx)['"]/ nocase ascii
    $cmd_yaml       = /(^|\n)[ \t]*command[ \t]*:[ \t]*['"]?(npx|uvx)\b/ nocase ascii
    $cmd_toml       = /(^|\n)[ \t]*command[ \t]*=[ \t]*['"](npx|uvx)['"]/ nocase ascii
    // -y / --yes then the package, or the package then the flag. Either quote. Any case.
    // Anchored on the args array so a pin or an allowlisted name elsewhere cannot veto the file.
    $flag_bare      = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"](--yes|-y)['"][ \t\r\n]*,[ \t\r\n]*['"][A-Za-z][A-Za-z0-9._-]{1,}['"]/ nocase ascii
    $bare_flag      = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"][A-Za-z][A-Za-z0-9._-]{1,}['"][ \t\r\n]*,[ \t\r\n]*['"](--yes|-y)['"]/ nocase ascii
    $flag_scoped    = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"](--yes|-y)['"][ \t\r\n]*,[ \t\r\n]*['"]@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+['"]/ nocase ascii
    $scoped_flag    = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"]@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+['"][ \t\r\n]*,[ \t\r\n]*['"](--yes|-y)['"]/ nocase ascii
    $one            = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,200}['"]-y[ \t]+(@[A-Za-z0-9._-]+\/)?[A-Za-z][A-Za-z0-9._-]*['"]/ nocase ascii
    // First args element is the package, so npx/uvx without -y still counts.
    $first_bare     = /['"](npx|uvx)['"][^\n]{0,200}['"]args['"][ \t]*:[ \t]*\[[ \t\r\n]*['"][A-Za-z][A-Za-z0-9._-]{1,}['"]/ nocase ascii
    $first_bare_nl  = /['"](npx|uvx)['"][^\n]*\n[ \t]*['"]args['"][^\n]*\n[ \t]*['"][A-Za-z][A-Za-z0-9._-]{1,}['"]/ nocase ascii
    $first_scoped   = /['"](npx|uvx)['"][^\n]{0,200}['"]args['"][ \t]*:[ \t]*\[[ \t\r\n]*['"]@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+['"]/ nocase ascii
    $yaml_pack      = /command:[ \t]*['"]?(npx|uvx)\b[^\n]*\n[^\n]*\n[^\n]*\n[ \t]*-[ \t]*[A-Za-z][A-Za-z0-9._-]{2,}/ nocase ascii
    $yaml_scoped    = /command:[ \t]*['"]?(npx|uvx)\b[^\n]*\n[^\n]*\n[^\n]*\n[ \t]*-[ \t]*@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+/ nocase ascii
    $off            = /@(modelcontextprotocol|anthropic|github)\// nocase ascii

  condition:
    (
      (filepath == "" and (uint8(0) == 0x7B or $start_yaml or $start_toml)) or
      (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
        not filepath matches /\.(md|markdown)$/i)
    ) and ($mcp_json or $mcp_yaml or $mcp_toml or $mcp_toml_table) and ($cmd_json or $cmd_yaml or $cmd_toml) and (
      $flag_bare or $bare_flag or $one or $first_bare or $first_bare_nl or $yaml_pack or
      for any i in (1..8): (
        i <= #flag_scoped and
        not for any k in (1..8): (
          k <= #off and @off[k] > @flag_scoped[i] and @off[k] < @flag_scoped[i] + !flag_scoped[i]
        )
      ) or
      for any i in (1..8): (
        i <= #scoped_flag and
        not for any k in (1..8): (
          k <= #off and @off[k] > @scoped_flag[i] and @off[k] < @scoped_flag[i] + !scoped_flag[i]
        )
      ) or
      for any i in (1..8): (
        i <= #first_scoped and
        not for any k in (1..8): (
          k <= #off and @off[k] > @first_scoped[i] and @off[k] < @first_scoped[i] + !first_scoped[i]
        )
      ) or
      for any i in (1..8): (
        i <= #yaml_scoped and
        not for any k in (1..8): (
          k <= #off and @off[k] > @yaml_scoped[i] and @off[k] < @yaml_scoped[i] + !yaml_scoped[i]
        )
      )
    )
}
