/*
   SERAPH-YARA-005
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SUSP_SERAPH_MCP_Secret_Exfil {
  meta:
    id               = "SERAPH-YARA-005"
    title            = "MCP config places a secret environment variable on a network sink"
    old_rule_name    = "SERAPH_MCP_Secret_Exfil"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.6.0"
    severity         = "critical"
    status           = "experimental"
    score            = 75
    description      = "Detects an MCP client config that sends a well-known API token to a host that is not that token's vendor, pipes or substitutes printenv or env into a fetch utility or nc, sends a credential file through a fetch utility, or reads a token from process.env inside a fetch call. A token used against its own vendor API does not match. A lookalike host such as github.com.attacker.example is not the vendor."
    attack_technique = "T1552.001, T1567"
    attack_tactic    = "credential-access, exfiltration"
    reference        = "https://attack.mitre.org/techniques/T1567/"
    reference        = "https://attack.mitre.org/techniques/T1552/001/"
    scope            = "MCP client configs: an mcpServers object, Codex mcp_servers tables, a VS Code servers object beside a command key, or Zed context_servers. Presence of a token variable in an env map is not enough. File types are JSON, JSONC, TOML, and YAML, any case, including .claude.json, *.json.bak, and *.json.backup*. Markdown does not match."
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
    $curl       = /curl [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b(\\"|[^\n"]){0,220}/ nocase ascii
    $wget       = /wget [^\n]{0,200}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b(\\"|[^\n"]){0,220}/ nocase ascii
    $url        = /https?:\/\/[^\s"']{0,180}\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b/ nocase ascii
    // The token is copied to another variable first, and the fetch comes later in the same string or the next argument.
    $acurl      = /[A-Za-z_][A-Za-z0-9_]*=\\?["']?\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b.{0,120}(curl|wget) [^\n]{0,200}/s nocase ascii
    // Node reads the token from process.env inside a fetch call.
    $nfetch     = /(fetch|axios[.A-Za-z]*|got|https?\.(get|request))[ \t]*\([^\n]{0,200}process\.env(\.|\[\\?["'])(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CURSOR_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b[^\n]{0,100}/ nocase ascii
    // The whole environment, or a credential file, goes to a fetch utility.
    $sub_env    = /(curl|wget)[ \t][^\n]{0,200}(\$\(|`)[ \t]*(printenv|env)[ \t]*(\||\)|`)/ nocase ascii
    $cred_pipe  = /(cat|base64|tar|gzip)[ \t]+[^\n|]{0,80}(\.aws\/credentials|\.ssh\/id_[a-z0-9]+|\.npmrc|\.netrc|\.git-credentials|\.docker\/config\.json|\.config\/gh\/hosts\.yml|\.kube\/config)[^\n|]{0,40}\|[^\n]{0,60}(curl|wget|nc)[ \t]/ nocase ascii
    $cred_post  = /(curl|wget)[^\n]{0,200}(@|\$\(cat[ \t]+|(-T|--upload-file)[ \t]+)[^ \t"'\n]{0,40}(\.aws\/credentials|\.ssh\/id_[a-z0-9]+|\.npmrc|\.netrc|\.git-credentials|\.docker\/config\.json|\.config\/gh\/hosts\.yml|\.kube\/config)/ nocase ascii
    $printenv   = /\b(printenv|env)[ \t]*\|[^\n]{0,60}(curl |wget |nc )/ nocase ascii
    // An escaped quote followed by the quote that closes the JSON string also ends the host.
    // A vendor host has to end where the URL's authority ends, so
    // github.com.attacker.example and github.com@attacker.example are not GitHub.
    // AWS secrets have no vendor host here: a SigV4 secret is never sent, and
    // anyone can own a bucket under amazonaws.com.
    // The Google API key reaches the Google-operated hosts that take a key, such as
    // www, maps, places, and youtube. storage.googleapis.com is not listed: a bucket
    // there belongs to whoever created it.
    // Vendor URL first, then that vendor's token, on one line.
    $off_a      = /https?:\/\/([A-Za-z0-9-]+\.)*github\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?(GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN)\b|https?:\/\/([A-Za-z0-9-]+\.)*openai\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?(OPENAI_API_KEY)\b|https?:\/\/([A-Za-z0-9-]+\.)*(anthropic\.com|claude\.ai|claude\.com)(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?(ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b|https?:\/\/([A-Za-z0-9-]+\.)*npmjs\.org(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?(NPM_TOKEN)\b|https?:\/\/([A-Za-z0-9-]+\.)*cursor\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?(CURSOR_API_KEY)\b|https?:\/\/([A-Za-z0-9-]+\.)*((generativelanguage|www|maps|places|routes|youtube|translation|vision|texttospeech|speech|language|customsearch|safebrowsing)\.googleapis\.com|ai\.google\.dev)(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))[^\n]{0,220}\$\{?(GEMINI_API_KEY|GOOGLE_API_KEY)\b/ nocase ascii
    // That vendor's token first, then the vendor URL, on one line.
    $off_b      = /\$\{?(GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*github\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?(OPENAI_API_KEY)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*openai\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?(ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*(anthropic\.com|claude\.ai|claude\.com)(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?(NPM_TOKEN)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*npmjs\.org(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?(CURSOR_API_KEY)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*cursor\.com(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))|\$\{?(GEMINI_API_KEY|GOOGLE_API_KEY)\b[^\n]{0,220}https?:\/\/([A-Za-z0-9-]+\.)*((generativelanguage|www|maps|places|routes|youtube|translation|vision|texttospeech|speech|language|customsearch|safebrowsing)\.googleapis\.com|ai\.google\.dev)(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))/ nocase ascii
    $anyurl     = /https?:\/\/[^ \t\r\n"'\/?#\\]{1,255}/ nocase ascii
    $ven_any    = /https?:\/\/([A-Za-z0-9-]+\.)*(github\.com|openai\.com|(anthropic\.com|claude\.ai|claude\.com)|npmjs\.org|cursor\.com|((generativelanguage|www|maps|places|routes|youtube|translation|vision|texttospeech|speech|language|customsearch|safebrowsing)\.googleapis\.com|ai\.google\.dev))(\/|\?|#|[ \t\r\n]|$|\\""|\\?["')>`]([ \t\r\n,;\]}]|$))/ nocase ascii

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
      $printenv or $sub_env or $cred_pipe or $cred_post or
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
      for any i in (1..256): (
        i <= #acurl and (
          not ($off_a in (@acurl[i]..@acurl[i] + !acurl[i] - 1) or $off_b in (@acurl[i]..@acurl[i] + !acurl[i] - 1)) or
          #anyurl in (@acurl[i]..@acurl[i] + !acurl[i] - 1) > #ven_any in (@acurl[i]..@acurl[i] + !acurl[i] - 1)
        )
      ) or
      // process.env in a fetch call is a leak when the URLs in the call are not all the vendor's.
      for any i in (1..256): (
        i <= #nfetch and #anyurl in (@nfetch[i]..@nfetch[i] + !nfetch[i] - 1) > #ven_any in (@nfetch[i]..@nfetch[i] + !nfetch[i] - 1)
      ) or
      // A token inside a URL is official only when that URL is the vendor's own.
      for any i in (1..256): (
        i <= #url and not $off_a at @url[i]
      )
    )
}
