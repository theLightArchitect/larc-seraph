/*
   SERAPH-YARA-003
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Encoded_Exec_Path {
  meta:
    id               = "SERAPH-YARA-003-PATH"
    title            = "MCP config decodes a payload into a shell or eval"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.4.0"
    severity         = "high"
    status           = "experimental"
    score            = "75"
    description      = "Detects an MCP client config that pipes a base64 decode into a shell, or pairs a base64 decode call with eval or exec. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1027, T1140, T1059.004"
    attack_tactic    = "defense-evasion, execution"
    reference        = "https://attack.mitre.org/techniques/T1027/"
    reference_2      = "https://attack.mitre.org/techniques/T1140/"
    reference_3      = "https://attack.mitre.org/techniques/T1059/004/"
    scope            = "MCP client configs: an mcpServers object, Codex mcp_servers tables, a VS Code servers object beside a command key, or Zed context_servers. A long token alone is not enough. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
    false_positives  = "A server whose documented command line legitimately shells out through a decode step. Rare in MCP configs. The rule does not flag a bare base64 blob."
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
    $dec_sh     = /base64[ \t]+(-[dD]|--decode)\b[^\n]{0,80}\|\s*(ba)?sh\b/ nocase ascii
    $dec_zsh    = /base64[ \t]+(-[dD]|--decode)\b[^\n]{0,80}\|\s*zsh\b/ nocase ascii
    $py_fwd     = /b64decode.{0,80}(eval|exec)\s*\(/s nocase ascii
    $py_rev     = /(eval|exec)\s*\(.{0,80}b64decode/s nocase ascii
    $urllib     = /urllib\.request\.urlopen.{0,180}(eval|exec)\s*\(/s nocase ascii
    $urllib_rev = /(eval|exec)\s*\(.{0,120}urlopen/s nocase ascii

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
    ) and ($mcp or $mcp_yaml or $mcp_toml or $mcp_table or $mcp_zed or ($mcp_vscode and $cmd_key)) and any of ($dec_sh, $dec_zsh, $py_fwd, $py_rev, $urllib, $urllib_rev)
}
