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
    version          = "1.3.0"
    severity         = "high"
    status           = "experimental"
    score            = "75"
    description      = "Detects an MCP client config that pipes a base64 decode into a shell, or pairs a base64 decode call with eval or exec. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1027, T1140, T1059.004"
    attack_tactic    = "defense-evasion, execution"
    reference        = "https://attack.mitre.org/techniques/T1027/"
    reference_2      = "https://attack.mitre.org/techniques/T1140/"
    reference_3      = "https://attack.mitre.org/techniques/T1059/004/"
    scope            = "MCP client configs that contain an mcpServers object. A long token alone is not enough. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
    false_positives  = "A server whose documented command line legitimately shells out through a decode step. Rare in MCP configs. The rule does not flag a bare base64 blob."
    license          = "Detection Rule License 1.1"

  strings:
    $mcp        = "\"mcpServers\"" ascii
    $mcp_yaml   = /mcpServers[ \t]*:/ ascii
    $mcp_toml   = /mcp_servers[ \t]*=/ ascii
    $dec_sh     = /base64[ \t]+(-[dD]|--decode)\b[^\n]{0,80}\|\s*(ba)?sh\b/ nocase ascii
    $dec_zsh    = /base64[ \t]+(-[dD]|--decode)\b[^\n]{0,80}\|\s*zsh\b/ nocase ascii
    $py_fwd     = /b64decode.{0,80}(eval|exec)\s*\(/s nocase ascii
    $py_rev     = /(eval|exec)\s*\(.{0,80}b64decode/s nocase ascii
    $urllib     = /urllib\.request\.urlopen.{0,180}(eval|exec)\s*\(/s nocase ascii
    $urllib_rev = /(eval|exec)\s*\(.{0,120}urlopen/s nocase ascii

  condition:
    (
      (filepath == "" and uint8(0) == 0x7B) or
      (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
        not filepath matches /\.(md|markdown)$/i)
    ) and ($mcp or $mcp_yaml or $mcp_toml) and any of ($dec_sh, $dec_zsh, $py_fwd, $py_rev, $urllib, $urllib_rev)
}
