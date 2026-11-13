/*
   SERAPH-YARA-001
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Launch_From_Temp {
  meta:
    id               = "SERAPH-YARA-001"
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
    description      = "Detects an MCP client config that sets a server command to a temp, cache, or shared-memory path, or points a shell at a script in one of those paths."
    attack_technique = "T1059.004"
    attack_tactic    = "execution"
    reference        = "https://attack.mitre.org/techniques/T1059/004/"
    reference_2      = "https://modelcontextprotocol.io/specification/2025-06-18"
    scope            = "MCP client configs: an mcpServers object, Codex mcp_servers tables, a VS Code servers object beside a command key, or Zed context_servers. Pair with a path filter such as mcp.json or claude_desktop_config.json. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
    false_positives  = "A short-lived local experiment that intentionally runs a server from /tmp or Library/Caches. A bare /tmp directory grant with no trailing path segment is not matched."
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

    // The key may be quoted (JSON) or bare (TOML, YAML). The value may be quoted or bare.
    $cmd_tmp   = /(["' \t\n{,]|^)command["']?\s*[:=]\s*["']?(\/tmp\/|\/private\/tmp\/|\/var\/folders\/|\/var\/tmp\/|\/dev\/shm\/)[^"'\n]{0,180}/ ascii
    $cmd_cache = /(["' \t\n{,]|^)command["']?\s*[:=]\s*["']?[^"'\n]{0,180}\/Library\/Caches\/[^"'\n]{0,120}/ ascii

    $shell     = /(["' \t\n{,]|^)command["']?\s*[:=]\s*["']?(\/bin\/bash|\/bin\/sh|\/bin\/zsh|\/usr\/bin\/python3?|\/usr\/bin\/osascript)(["']|[ \t\r]*\n)/ ascii
    // A quoted string, or a YAML list item.
    $arg_tmp   = /(["']|\n[ \t]*-[ \t]+)(\/tmp\/|\/private\/tmp\/|\/var\/folders\/|\/var\/tmp\/|\/dev\/shm\/)[^"'\n]{0,180}/ ascii
    $arg_cache = /(["']|\n[ \t]*-[ \t]+)[^"'\n]{0,80}\/Library\/Caches\/[^"'\n]{0,160}/ ascii

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
    ) and ($mcp or $mcp_yaml or $mcp_toml or $mcp_table or $mcp_zed or ($mcp_vscode and $cmd_key)) and (
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
