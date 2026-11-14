/*
   SERAPH-YARA-016
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.
*/

rule SUSP_SERAPH_MCP_Unpinned_Package_Path {
  meta:
    id               = "SERAPH-YARA-016-PATH"
    title            = "MCP config runs an unpinned npx or uvx package"
    old_rule_name    = "SERAPH_MCP_Unpinned_Package_Path"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.7.0"
    severity         = "medium"
    status           = "experimental"
    score            = 55
    description      = "Detects an MCP client config that starts npx, uvx, bunx, npm exec, pnpm dlx, yarn dlx, or uv tool run with a package that has no numeric version and is not an allowlisted first-party scope. Remote URLs and explicit @latest tags are SERAPH-YARA-004. A pin or an allowlisted package elsewhere in the file does not clear a second unpinned package. Path-scoped variant. It requires the filepath external and is not for YARA-Forge."
    attack_technique = "T1195.002"
    attack_tactic    = "initial-access"
    reference        = "https://attack.mitre.org/techniques/T1195/002/"
    reference        = "https://modelcontextprotocol.io/specification/2025-06-18"
    reference        = "https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/"
    scope            = "JSON, TOML, or YAML MCP configs, including Codex mcp_servers tables, a VS Code servers object, and Zed context_servers. Markdown docs do not match. Allowlisted scopes are @modelcontextprotocol, @anthropic-ai, and @github. A package token that itself contains @ and a version does not match. @latest is SERAPH-YARA-004."
    false_positives  = "A community MCP server installed the way its README shows, with npx and no version. The allowlist is short on purpose. Review the package name. npm exec and pnpm dlx read a bare name as a package, as npx does, so a project-local binary run as npm exec -- tsc also matches: a rule cannot tell a local binary from a package npm would download."
    license          = "Detection Rule License 1.1"

  strings:
    $mcp_json        = /['"]mcpServers['"][ \t]*:/ ascii
    $mcp_yaml        = /mcpServers[ \t]*:/ ascii
    $mcp_toml        = /mcp_servers[ \t]*=/ ascii
    $mcp_toml_table  = /\[mcp_servers/ ascii
    // VS Code writes "servers" and Zed writes "context_servers".
    $mcp_vscode      = /"servers"[ \t\r\n]*:[ \t\r\n]*\{/ ascii
    $mcp_zed         = "\"context_servers\"" ascii
    $start_yaml      = /^mcpServers[ \t]*:/ ascii
    $start_toml      = /^(\[mcp_servers|mcp_servers[ \t]*=)/ ascii
    // The runner by name or by absolute path.
    $cmd_json        = /['"]command['"][ \t]*:[ \t]*['"]([^'"\n]{0,80}\/)?(npx|uvx|bunx)['"]/ nocase ascii
    $cmd_yaml        = /(^|\n)[ \t]*command[ \t]*:[ \t]*['"]?(npx|uvx|bunx)\b/ nocase ascii
    $cmd_toml        = /(^|\n)[ \t]*command[ \t]*=[ \t]*['"](npx|uvx|bunx)['"]/ nocase ascii
    // -y / --yes then the package, or the package then the flag. Either quote. Any case.
    // Anchored on the args array so a pin or an allowlisted name elsewhere cannot veto the file.
    $flag_bare       = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"](--yes|-y)['"][ \t\r\n]*,[ \t\r\n]*(['"]-{1,2}([A-Za-z][A-Za-z-]*)?['"][ \t\r\n]*,[ \t\r\n]*){0,4}['"][A-Za-z][A-Za-z0-9._-]{1,}['"]/ nocase ascii
    $bare_flag       = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"][A-Za-z][A-Za-z0-9._-]{1,}['"][ \t\r\n]*,[ \t\r\n]*['"](--yes|-y)['"]/ nocase ascii
    $flag_scoped     = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"](--yes|-y)['"][ \t\r\n]*,[ \t\r\n]*(['"]-{1,2}([A-Za-z][A-Za-z-]*)?['"][ \t\r\n]*,[ \t\r\n]*){0,4}['"]@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+['"]/ nocase ascii
    $flag_scoped_ok  = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"](--yes|-y)['"][ \t\r\n]*,[ \t\r\n]*(['"]-{1,2}([A-Za-z][A-Za-z-]*)?['"][ \t\r\n]*,[ \t\r\n]*){0,4}['"]@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+['"]/ nocase ascii
    $scoped_flag     = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"]@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+['"][ \t\r\n]*,[ \t\r\n]*['"](--yes|-y)['"]/ nocase ascii
    $scoped_flag_ok  = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}['"]@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+['"][ \t\r\n]*,[ \t\r\n]*['"](--yes|-y)['"]/ nocase ascii
    $one             = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,200}['"]-y[ \t]+(@[A-Za-z0-9._-]+\/)?[A-Za-z][A-Za-z0-9._-]*['"]/ nocase ascii
    // First args element is the package, so npx/uvx without -y still counts.
    $first_bare      = /['"](npx|uvx|bunx)['"][^\n]{0,200}['"]args['"][ \t]*:[ \t]*\[[ \t\r\n]*['"][A-Za-z][A-Za-z0-9._-]{1,}['"]/ nocase ascii
    $first_bare_nl   = /['"](npx|uvx|bunx)['"][^\n]*\n[ \t]*['"]args['"][^\n]*\n[ \t]*['"][A-Za-z][A-Za-z0-9._-]{1,}['"]/ nocase ascii
    $first_scoped    = /['"](npx|uvx|bunx)['"][^\n]{0,200}['"]args['"][ \t]*:[ \t]*\[[ \t\r\n]*['"]@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+['"]/ nocase ascii
    $first_scoped_ok = /['"](npx|uvx|bunx)['"][^\n]{0,200}['"]args['"][ \t]*:[ \t]*\[[ \t\r\n]*['"]@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+['"]/ nocase ascii
    $yaml_pack       = /command:[ \t]*['"]?(npx|uvx|bunx)\b[^\n]*\n[^\n]*\n[^\n]*\n[ \t]*-[ \t]*[A-Za-z][A-Za-z0-9._-]{2,}/ nocase ascii
    $yaml_scoped     = /command:[ \t]*['"]?(npx|uvx|bunx)\b[^\n]*\n[^\n]*\n[^\n]*\n[ \t]*-[ \t]*@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+/ nocase ascii
    $yaml_scoped_ok  = /command:[ \t]*['"]?(npx|uvx|bunx)\b[^\n]*\n[^\n]*\n[^\n]*\n[ \t]*-[ \t]*@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+/ nocase ascii

    // Runners that are not the command itself. Each reads the package from an args array.
    $dlx_bare        = /["'](pnpm|yarn|npm)["'][^}]{0,200}["']args["'][ \t]*[:=][ \t]*\[[ \t\r\n]*["'](dlx|exec)["'][ \t\r\n]*,[ \t\r\n]*(['"]-{1,2}([A-Za-z][A-Za-z-]*)?['"][ \t\r\n]*,[ \t\r\n]*){0,4}["'][A-Za-z][A-Za-z0-9._-]{1,}["']/ nocase ascii
    $dlx_scoped      = /["'](pnpm|yarn|npm)["'][^}]{0,200}["']args["'][ \t]*[:=][ \t]*\[[ \t\r\n]*["'](dlx|exec)["'][ \t\r\n]*,[ \t\r\n]*(['"]-{1,2}([A-Za-z][A-Za-z-]*)?['"][ \t\r\n]*,[ \t\r\n]*){0,4}["']@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+["']/ nocase ascii
    $dlx_scoped_ok   = /["'](pnpm|yarn|npm)["'][^}]{0,200}["']args["'][ \t]*[:=][ \t]*\[[ \t\r\n]*["'](dlx|exec)["'][ \t\r\n]*,[ \t\r\n]*(['"]-{1,2}([A-Za-z][A-Za-z-]*)?['"][ \t\r\n]*,[ \t\r\n]*){0,4}["']@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+["']/ nocase ascii
    $uv_bare         = /["'](uv)["'][^}]{0,200}["']args["'][ \t]*[:=][ \t]*\[[ \t\r\n]*["']tool["'][ \t\r\n]*,[ \t\r\n]*["']run["'][ \t\r\n]*,[ \t\r\n]*(['"]-{1,2}([A-Za-z][A-Za-z-]*)?['"][ \t\r\n]*,[ \t\r\n]*){0,4}["'][A-Za-z][A-Za-z0-9._-]{1,}["']/ nocase ascii
    // Windows starts npx through cmd /c.
    $win_runner      = /["'](cmd|cmd\.exe)["'][^}]{0,100}["']\/c["'][ \t\r\n]*,[ \t\r\n]*["'](npx|bunx|uvx)(\.cmd)?["']/ nocase ascii
    // npx -y pkg inside one shell string. -y marks a remote install, so npx tsc is not matched.
    $sh_npx          = /(["' \t;&|(`]|^)(npx|bunx|uvx)[ \t]+(-y|--yes)[ \t]+(-{1,2}[A-Za-z][A-Za-z-]*[ \t]+){0,3}[A-Za-z][A-Za-z0-9._-]{1,}(["'\\ \t;&|)]|$)/ nocase ascii
    $sh_scoped       = /(["' \t;&|(`]|^)(npx|bunx|uvx)[ \t]+(-y|--yes)[ \t]+(-{1,2}[A-Za-z][A-Za-z-]*[ \t]+){0,3}@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(["'\\ \t;&|)]|$)/ nocase ascii
    $sh_scoped_ok    = /(["' \t;&|(`]|^)(npx|bunx|uvx)[ \t]+(-y|--yes)[ \t]+(-{1,2}[A-Za-z][A-Za-z-]*[ \t]+){0,3}@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+(["'\\ \t;&|)]|$)/ nocase ascii
    // --package=name names the package. A pin on it is a numeric version.
    $pkgeq           = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}["'](--package|-p)=[A-Za-z][A-Za-z0-9._-]{1,}["']/ nocase ascii
    $pkgeq_scoped    = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}["'](--package|-p)=@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+["']/ nocase ascii
    $pkgeq_scoped_ok = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}["'](--package|-p)=@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+["']/ nocase ascii
    // A range is not a pin.
    $range           = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}["'][A-Za-z][A-Za-z0-9._-]{1,}@[\^~><][^"'\n]{0,30}["']/ nocase ascii
    $range_scoped    = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}["']@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+@[\^~><][^"'\n]{0,30}["']/ nocase ascii
    $range_scoped_ok = /args['"]?[ \t]*[:=][ \t]*\[[^\]]{0,300}["']@(modelcontextprotocol|anthropic-ai|github)\/[A-Za-z0-9._-]+@[\^~><][^"'\n]{0,30}["']/ nocase ascii

  condition:
    (
      (filepath == "" and not for 8 i in (0..1023): (uint8(i) < 9 or (uint8(i) > 13 and uint8(i) < 32 and uint8(i) != 27)) and (for any i in (0..4095): (
            uint8(i) == 0x7B and
            for all j in (0..i): (
              j == i or uint8(j) == 0x20 or uint8(j) == 0x09 or uint8(j) == 0x0A or uint8(j) == 0x0D or
              uint8(j) == 0xEF or uint8(j) == 0xBB or uint8(j) == 0xBF
            )
          ) or $start_yaml or $start_toml)) or
      (filepath != "" and filepath matches /\.(json|jsonc|toml|yml|yaml)(\.bak|\.backup[^\/]*)?$/i and
        not filepath matches /\.(md|markdown)$/i)
    ) and ($mcp_json or $mcp_yaml or $mcp_toml or $mcp_toml_table or $mcp_vscode or $mcp_zed) and (
      (($cmd_json or $cmd_yaml or $cmd_toml or $win_runner) and (
          $flag_bare or $bare_flag or $one or $first_bare or $first_bare_nl or $yaml_pack or
          $pkgeq or $range or
          // The same pattern with an allowlisted scope on the package token. More scoped
          // packages than allowlisted ones means one of them is not allowlisted. A scope
          // name elsewhere in the args, such as a registry URL, does not count.
          #flag_scoped > #flag_scoped_ok or
          #scoped_flag > #scoped_flag_ok or
          #first_scoped > #first_scoped_ok or
          #yaml_scoped > #yaml_scoped_ok or
          #pkgeq_scoped > #pkgeq_scoped_ok or
          #range_scoped > #range_scoped_ok
        )) or
      $dlx_bare or $uv_bare or $sh_npx or
      #dlx_scoped > #dlx_scoped_ok or
      #sh_scoped > #sh_scoped_ok
    )
}
