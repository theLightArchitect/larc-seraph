/*
   SERAPH-YARA-002
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Curl_Pipe_Shell {
  meta:
    id               = "SERAPH-YARA-002"
    title            = "MCP config pipes a remote fetch into a shell"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.3.0"
    severity         = "critical"
    status           = "experimental"
    score            = 80
    description      = "Detects an MCP client config that contains a fetch utility immediately piped into sh, bash, or zsh, a process substitution that feeds a fetch into a shell, or a shell or eval that runs a fetch through command substitution."
    attack_technique = "T1059.004, T1105"
    attack_tactic    = "execution, command-and-control"
    reference        = "https://attack.mitre.org/techniques/T1059/004/"
    reference        = "https://attack.mitre.org/techniques/T1105/"
    scope            = "MCP client configs: an mcpServers object, Codex mcp_servers tables, a VS Code servers object beside a command key, or Zed context_servers. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
    false_positives  = "A config that quotes this anti-pattern in a long description field on the same line as a fetch. Review the command and args before deleting a server entry."
    license          = "Detection Rule License 1.1"

  strings:
    // What follows the shell name has to end the command or start an argument,
    // so a Markdown table cell (| zsh |) and a longer word (dash-case) are not a shell.
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
    // A shell by any usual name, with an optional sudo or directory, and |& as well as |.
    $pipe_curl  = /(curl|wget)[^\n]{0,200}\|&?\s*(sudo\s+)?(\/[a-z\/]{1,20}\/)?(ba|z|da|k|fi)?sh(\\?["'`;&)]|[.,:]([ \t\r\n]|$)|[ \t]+[^| \t\r\n]|[ \t]*\r?\n|[ \t]*$)/ nocase ascii
    $subst      = /((ba|z|da|k)?sh|source)\s+<\s*\(\s*(curl|wget)/ nocase ascii
    // sh -c \"$(curl ...)\" and eval \"$(curl ...)\". The quote may be JSON-escaped.
    $cmdsub     = /((ba|z|da|k)?sh\s+-c|eval|source)\s+\\?["']?\$\(\s*(curl|wget)/ nocase ascii

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
    ) and ($mcp or $mcp_yaml or $mcp_toml or $mcp_table or $mcp_zed or ($mcp_vscode and $cmd_key)) and any of ($pipe_curl, $subst, $cmdsub)
}
