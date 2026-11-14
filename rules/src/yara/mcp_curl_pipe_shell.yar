/*
   SERAPH-YARA-002
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SUSP_SERAPH_MCP_Curl_Pipe_Shell {
  meta:
    id               = "SERAPH-YARA-002"
    title            = "MCP config pipes a remote fetch into a shell"
    old_rule_name    = "SERAPH_MCP_Curl_Pipe_Shell"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.4.0"
    severity         = "critical"
    status           = "experimental"
    score            = 80
    description      = "Detects an MCP client config that contains a fetch utility piped into a shell or a bare interpreter, a fetch written to a file and run in the same string, a process or command substitution that feeds a fetch into a shell, or Python that passes a fetched body to a system call. JSON escapes of the pipe, a letter of the fetch name, and the gap after the pipe do not hide it."
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
    $mcp         = "\"mcpServers\"" ascii
    $mcp_yaml    = /mcpServers[ \t]*:/ ascii
    $mcp_toml    = /mcp_servers[ \t]*=/ ascii
    $mcp_table   = /\[mcp_servers[.\]]/ ascii
    // VS Code writes "servers" and Zed writes "context_servers". "servers" is a
    // common key, so it only counts beside a command key.
    $mcp_vscode  = /"servers"[ \t\r\n]*:[ \t\r\n]*\{/ ascii
    $mcp_zed     = "\"context_servers\"" ascii
    $cmd_key     = /(["' \t\n{,]|^)command["']?[ \t]*[:=]/ ascii
    // With no path to consult, the file has to be text (fewer than eight control bytes in
    // the first kilobyte), and the condition accepts a JSON object after an optional
    // BOM and blank space (a leading comment is not accepted, because source files start that way), a top-level mcpServers: key, or an mcp_servers table.
    $yaml_top    = /(^|\n)mcpServers[ \t]*:/ ascii
    $toml_top    = /(^|\n)(\[mcp_servers[.\]]|mcp_servers[ \t]*=)/ ascii
    // A shell by any usual name, with an optional sudo or directory, and |& as well as |.
    // JSON can spell a letter of the fetch name as \u00XX, the pipe as \u007c, and the gap after it as \n.
    $pipe_curl   = /((c|\\u0063)(u|\\u0075)(r|\\u0072)(l|\\u006c)|(w|\\u0077)(g|\\u0067)(e|\\u0065)(t|\\u0074))[^\n]{0,200}(\||\\u007c)&?(\s|\\[nrt])*(sudo\s+)?(\/[a-z\/]{1,20}\/)?(ba|z|da|k|fi)?sh(\\?["'`;&)]|[.,:]([ \t\r\n]|$)|[ \t]+[^| \t\r\n]|[ \t]*\r?\n|[ \t]*$)/ nocase ascii
    // A bare interpreter reads the fetched script from standard input. python3 -m json.tool is not one.
    $pipe_interp = /((c|\\u0063)(u|\\u0075)(r|\\u0072)(l|\\u006c)|(w|\\u0077)(g|\\u0067)(e|\\u0065)(t|\\u0074))[^\n]{0,200}(\||\\u007c)&?(\s|\\[nrt])*(sudo\s+)?(\/[a-z\/]{1,20}\/)?(python3?|node|perl|ruby)([ \t]+-)?(\\?["'`;&)]|[ \t]*\r?\n|[ \t]*$)/ nocase ascii
    // Fetch to a file, then run that file in the same string.
    $dl_run      = /(curl|wget)[^\n]{0,200}(-[A-Za-z]*[oO][ \t]+|--output[ \t=]+|--output-document[ \t=]+|>[ \t]*)[^ \t"'\n;&|]{1,100}[ \t]*(&&|;)[ \t]*(sudo[ \t]+)?((\/[a-z\/]{1,20}\/)?(ba|z|da|k)?sh[ \t]+(-[A-Za-z]+[ \t]+)*[^ \t"'\n;&|]|source[ \t]+[^ \t"'\n;&|]|chmod[ \t]+[+0-7ugoax=-]+[ \t]+[^ \t"'\n;&|]+[ \t]*(&&|;)[ \t]*[^ \t"'\n;&|])/ nocase ascii
    // httpie and xh take the place of curl.
    $httpie      = /(["' \t;&|(`]|\\n)(http|https|xh)[ \t]+(-{1,2}[A-Za-z][A-Za-z-]*[ \t]+){0,4}(GET[ \t]+)?https?:\/\/[^\n]{0,200}(\||\\u007c)&?(\s|\\[nrt])*(sudo\s+)?(\/[a-z\/]{1,20}\/)?(ba|z|da|k|fi)?sh(\\?["'`;&)]|[.,:]([ \t\r\n]|$)|[ \t]+[^| \t\r\n]|[ \t]*\r?\n|[ \t]*$)/ nocase ascii
    // Python that hands a fetched body to a system call.
    $py_sys      = /(os\.system|os\.popen|subprocess\.[A-Za-z_]+)[ \t]*\(.{0,160}urlopen/s ascii
    $py_sys_fwd  = /urlopen.{0,200}os\.(system|popen)[ \t]*\(/s ascii
    $subst       = /((ba|z|da|k)?sh|source)\s+<\s*\(\s*(curl|wget)/ nocase ascii
    // sh -c \"$(curl ...)\" and eval \"$(curl ...)\". The quote may be JSON-escaped.
    $cmdsub      = /(((ba|z|da|k)?sh\s+-c|eval|source)\s+\\?["']?\$\(\s*(curl|wget)|-c["']?[ \t\r\n]*,[ \t\r\n]*\\?["'](\$\(|`)[ \t]*(curl|wget))/ nocase ascii

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
    ) and ($mcp or $mcp_yaml or $mcp_toml or $mcp_table or $mcp_zed or ($mcp_vscode and $cmd_key)) and any of ($pipe_curl, $pipe_interp, $dl_run, $httpie, $py_sys, $py_sys_fwd, $subst, $cmdsub)
}
