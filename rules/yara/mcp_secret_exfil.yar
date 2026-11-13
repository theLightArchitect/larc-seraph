/*
   SERAPH-YARA-005
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SERAPH_MCP_Secret_Exfil {
  meta:
    id               = "SERAPH-YARA-005"
    title            = "MCP config places a secret environment variable on a network sink"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.5.0"
    severity         = "critical"
    status           = "experimental"
    score            = 75
    description      = "Detects an MCP client config that sends a well-known API token to a host that is not that token's vendor, or pipes printenv or env into a fetch utility or nc. A token used against its own vendor API does not match. A lookalike host such as github.com.attacker.example is not the vendor. Content-only rule: it compiles with no externals."
    attack_technique = "T1552.001, T1567"
    attack_tactic    = "credential-access, exfiltration"
    reference        = "https://attack.mitre.org/techniques/T1567/"
    reference        = "https://attack.mitre.org/techniques/T1552/001/"
    scope            = "MCP client configs: an mcpServers object, Codex mcp_servers tables, a VS Code servers object beside a command key, or Zed context_servers. Presence of a token variable in an env map is not enough. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match. The Forge rule has no path. It needs a JSON object at the start of the file (after an optional BOM or blank space), a top-level mcpServers: key, or an mcp_servers table. A JSONC file that opens with a comment, and Markdown, do not match."
    false_positives  = "A proxy or mirror of a vendor API on another host. An AWS secret beside any URL matches, because that secret signs requests and is not sent."
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
    $curl       = /curl [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b(\\"|[^\n"]){0,220}/ nocase ascii
    $wget       = /wget [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b(\\"|[^\n"]){0,220}/ nocase ascii
    $url        = /https?:\/\/[^\s"']{0,180}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY)\b/ nocase ascii
    $printenv   = /\b(printenv|env)[ \t]*\|[^\n]{0,60}(curl |wget |nc )/ nocase ascii
    // An escaped quote followed by the quote that closes the JSON string also ends the host.
    // A vendor host has to end where the URL's authority ends, so
    // github.com.attacker.example and github.com@attacker.example are not GitHub.
    // AWS secrets have no vendor host here: a SigV4 secret is never sent, and
    // anyone can own a bucket under amazonaws.com.
    // Vendor URL first, then that vendor's token, on one line.
    $off_a      = /https?:\/\/([A-Za-z0-9-]+\.)*github\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?(GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN)\b|https?:\/\/([A-Za-z0-9-]+\.)*openai\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?OPENAI_API_KEY\b|https?:\/\/([A-Za-z0-9-]+\.)*anthropic\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?ANTHROPIC_API_KEY\b|https?:\/\/([A-Za-z0-9-]+\.)*npmjs\.org(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?NPM_TOKEN\b|https?:\/\/([A-Za-z0-9-]+\.)*cursor\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?CURSOR_API_KEY\b/ nocase ascii
    // That vendor's token first, then the vendor URL, on one line.
    $off_b      = /\$\{?(GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*github\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?OPENAI_API_KEY\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*openai\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?ANTHROPIC_API_KEY\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*anthropic\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?NPM_TOKEN\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*npmjs\.org(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?CURSOR_API_KEY\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*cursor\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))/ nocase ascii
    $anyurl     = /https?:\/\/[^ \t\r\n"'\/?#\\]{1,255}/ nocase ascii
    $ven_any    = /https?:\/\/([A-Za-z0-9-]+\.)*(github\.com|openai\.com|anthropic\.com|npmjs\.org|cursor\.com)(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))/ nocase ascii

  condition:
    (
      not for 8 i in (0..1023): (uint8(i) < 9 or (uint8(i) > 13 and uint8(i) < 32 and uint8(i) != 27)) and (for any i in (0..4095): (
          uint8(i) == 0x7B and
          for all j in (0..i): (
            j == i or uint8(j) == 0x20 or uint8(j) == 0x09 or uint8(j) == 0x0A or uint8(j) == 0x0D or
            uint8(j) == 0xEF or uint8(j) == 0xBB or uint8(j) == 0xBF
          )
        ) or $yaml_top or $toml_top)
    ) and ($mcp or $mcp_yaml or $mcp_toml or $mcp_table or $mcp_zed or ($mcp_vscode and $cmd_key)) and (
      $printenv or
      for any i in (1..256): (
        i <= #curl and (
          // Official only when the vendor URL, or the token that precedes it, is inside this fetch.
          not ($off_a in (@curl[i]..@curl[i] + !curl[i] - 1) or $off_b in (@curl[i]..@curl[i] + !curl[i] - 1)) or
          // The fetch string runs to the end of its quoted command, so a foreign URL
          // before or after the token wins over a vendor URL anywhere in it.
          #anyurl in (@curl[i]..@curl[i] + !curl[i] - 1) > #ven_any in (@curl[i]..@curl[i] + !curl[i] - 1)
        )
      ) or
      for any i in (1..256): (
        i <= #wget and (
          // Official only when the vendor URL, or the token that precedes it, is inside this fetch.
          not ($off_a in (@wget[i]..@wget[i] + !wget[i] - 1) or $off_b in (@wget[i]..@wget[i] + !wget[i] - 1)) or
          // The fetch string runs to the end of its quoted command, so a foreign URL
          // before or after the token wins over a vendor URL anywhere in it.
          #anyurl in (@wget[i]..@wget[i] + !wget[i] - 1) > #ven_any in (@wget[i]..@wget[i] + !wget[i] - 1)
        )
      ) or
      // A token inside a URL is official only when that URL is the vendor's own.
      for any i in (1..256): (
        i <= #url and not $off_a at @url[i]
      )
    )
}
