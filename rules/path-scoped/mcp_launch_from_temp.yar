/*
   SERAPH-YARA-001
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Launch_From_Temp_Path {
  meta:
    id               = "SERAPH-YARA-001-PATH"
    title            = "MCP config launches a server from a temp or cache path"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.2.0"
    severity         = "high"
    status           = "experimental"
    score            = "60"
    description      = "Detects an MCP client config that sets a server command to a temp, cache, or shared-memory path, or points a shell at a script in one of those paths. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1059.004"
    attack_tactic    = "execution"
    reference        = "https://attack.mitre.org/techniques/T1059/004/"
    reference_2      = "https://modelcontextprotocol.io/specification/2025-06-18"
    scope            = "MCP client configs that contain an mcpServers object. Pair with a path filter such as mcp.json or claude_desktop_config.json. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
    false_positives  = "A short-lived local experiment that intentionally runs a server from /tmp or Library/Caches. A bare /tmp directory grant with no trailing path segment is not matched."
    license          = "Detection Rule License 1.1"

  strings:
    $mcp      = "\"mcpServers\"" ascii
    $mcp_yaml = /mcpServers[ \t]*:/ ascii
    $mcp_toml = /mcp_servers[ \t]*=/ ascii

    $cmd_tmp   = /"command"\s*:\s*"(\/tmp\/|\/private\/tmp\/|\/var\/folders\/|\/var\/tmp\/|\/dev\/shm\/)[^"]{0,180}"/ ascii
    $cmd_cache = /"command"\s*:\s*"[^"]{0,180}\/Library\/Caches\/[^"]{0,120}"/ ascii

    $shell     = /"command"\s*:\s*"(\/bin\/bash|\/bin\/sh|\/bin\/zsh|\/usr\/bin\/python3?|\/usr\/bin\/osascript)"/ ascii
    $arg_tmp   = /"(\/tmp\/|\/private\/tmp\/|\/var\/folders\/|\/var\/tmp\/|\/dev\/shm\/)[^"]{0,180}"/ ascii
    $arg_cache = /"[^"]{0,80}\/Library\/Caches\/[^"]{0,160}"/ ascii

  condition:
    (
      (filepath == "" and uint8(0) == 0x7B) or
      (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
        not filepath matches /\.(md|markdown)$/i)
    ) and ($mcp or $mcp_yaml or $mcp_toml) and (
      $cmd_tmp or
      $cmd_cache or
      (
        $shell and $arg_tmp and
        (
          (@arg_tmp > @shell and @arg_tmp - @shell < 1500) or
          (@shell > @arg_tmp and @shell - @arg_tmp < 200)
        )
      ) or
      (
        $shell and $arg_cache and
        (
          (@arg_cache > @shell and @arg_cache - @shell < 1500) or
          (@shell > @arg_cache and @shell - @arg_cache < 200)
        )
      )
    )
}
