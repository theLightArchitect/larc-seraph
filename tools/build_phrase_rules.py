"""Generate the instruction YARA rule from larc_seraph.phrases.

The pattern strings in that module are the source. This writes
rules/src/yara/instruction_unsafe_directive.yar. --check fails when the
file drifts. tools/build_rule_flavors.py then writes both flavors.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from larc_seraph.phrases import (  # noqa: E402
    ABSOLUTE_VETO_PATTERNS,
    BINARY_GUARD_YARA,
    FETCH_PATTERN,
    HOST_END_PATTERN,
    NEGATED_CLI_FLAG_PATTERN,
    URL_PATTERN,
    byte_regex,
    line_regex,
    CLI_FLAG_PATTERN,
    CONFIRM_PATTERNS,
    CRED_FORWARD,
    CRED_REVERSE,
    HIGH_PATTERNS,
    HIGH_WORD_PATTERN,
    HOMO_HEX,
    INSTALLER_BODY_PATTERN,
    LINE_REACH,
    NEGATED_FETCH_PATTERN,
    OUTER_BOUND,
    TOOL_KEY_PATTERN,
    INJECT_FORWARD,
    INJECT_REVERSE,
    LOW_PATTERN,
    POISON_PATTERN,
    PIPE_PATTERN,
    CONCEAL_PATTERNS,
    DETAIL_PATTERN,
    ENCODE_PATTERN,
    EXFIL_PATTERN,
    RECIPIENT_PATTERNS,
    SENSITIVE_PATH_PATTERN,
    SIDENOTE_PATTERNS,
    SIGNAL_PATTERNS,
    TOKENS,
    VENDOR_HOST,
)

DESTINATION = ROOT / "rules" / "src" / "yara" / "instruction_unsafe_directive.yar"

def to_yara(pattern: str) -> str:
    """The byte regex the CLI compiles is the text of the YARA string."""
    return byte_regex(pattern)


def _line(body: str) -> str:
    return "/" + line_regex(body) + "/ nocase ascii"


# yara-x warns on a loop over (1..#string), and the pack compiles with no
# warnings. Inner checks therefore use the at / in operators and match counts,
# which have no bound. Only the outermost loop keeps one, and it is large.
_OUTER = OUTER_BOUND


def _span(name: str) -> str:
    return f"(@{name}[i]..@{name}[i] + !{name}[i] - 1)"


def _around(name: str, reach: int) -> str:
    return f"(math.max(0, @{name}[i] - {reach})..@{name}[i] + {reach})"


def _occurrence(name: str, *, needs_high: bool) -> str:
    span = _span(name)
    text = f"""for any i in (1..{_OUTER}): (
        i <= #{name} and
        not $bad in {span} and
        not ($soft in {span} and not $high in {span})"""
    if needs_high:
        text += f""" and
        $high in {span}"""
    # More occurrences than the loop judges count as a match.
    return text + f"\n      ) or\n      #{name} > {_OUTER}"


def _token_block(name: str, vendor: str | None) -> str:
    near = _around(name, 200)
    if vendor is None:
        foreign = f"$url in {near}"
    else:
        # Every vendor URL is also a $url match at the same offset, so more URLs
        # than vendor URLs in the window means one of them is foreign.
        foreign = f"#url in {near} > #{vendor} in {near}"
    return f"""for any i in (1..{_OUTER}): (
        i <= #{name} and
        {foreign} and
        $fetch in {near}
      )"""


def _near(left: str, right: str) -> str:
    return f"""for any i in (1..{_OUTER}): (
        i <= #{left} and
        ${right} in {_around(left, 400)}
      )"""


def render() -> str:
    strings: list[str] = [
        '    $desc             = "\\"description\\"" ascii',
        f"    $homo             = {HOMO_HEX}",
        f"    $file_then_fetch  = /{to_yara(CRED_FORWARD)}/ nocase ascii",
        f"    $fetch_then_file  = /{to_yara(CRED_REVERSE)}/ nocase ascii",
        f"    $inject_fwd       = /{to_yara(INJECT_FORWARD)}/ nocase ascii",
        f"    $inject_rev       = /{to_yara(INJECT_REVERSE)}/ nocase ascii",
        f"    $high             = /{to_yara(HIGH_WORD_PATTERN)}/ nocase ascii",
        f"    $soft             = /({to_yara(POISON_PATTERN)})|({to_yara(LOW_PATTERN)})/ nocase ascii",
        "    $bad              = /"
        + "|".join(to_yara(item) for item in ABSOLUTE_VETO_PATTERNS)
        + "/ nocase ascii",
        f"    $url              = /{to_yara(URL_PATTERN)}/ nocase ascii",
        f"    $fetch            = /{to_yara(FETCH_PATTERN)}/ nocase ascii",
    ]
    confirm_names: list[str] = []
    for index, pattern in enumerate(CONFIRM_PATTERNS, start=1):
        name = f"c{index}"
        confirm_names.append(name)
        strings.append(f"    ${name} = {_line(to_yara(pattern))}")
    high_names: list[str] = []
    for index, pattern in enumerate(HIGH_PATTERNS, start=1):
        name = f"h{index}"
        high_names.append(name)
        strings.append(f"    ${name} = {_line(to_yara(pattern))}")
    token_names: list[tuple[str, str | None]] = []
    for host in dict.fromkeys(VENDOR_HOST.values()):
        slug = host.split(".")[0]
        names = [item for item, value in VENDOR_HOST.items() if value == host]
        strings.append(f"    $tok_{slug} = /\\b(" + "|".join(names) + ")\\b/ ascii")
        strings.append(
            f"    $ven_{slug} = /https?:\\/\\/([A-Za-z0-9-]+\\.)*"
            + host.replace(".", "\\.")
            + to_yara(HOST_END_PATTERN)
            + "/ nocase ascii"
        )
        token_names.append((f"tok_{slug}", f"ven_{slug}"))
    # A token with no vendor host. Any URL beside it and a fetch is a match.
    orphans = [token for token in TOKENS if token not in VENDOR_HOST]
    if orphans:
        strings.append("    $tok_novendor = /\\b(" + "|".join(orphans) + ")\\b/ ascii")
        token_names.append(("tok_novendor", None))

    signal_names: list[str] = []
    for index, pattern in enumerate(SIGNAL_PATTERNS, start=1):
        name = f"s{index}"
        signal_names.append(name)
        strings.append(f"    ${name}              = /{to_yara(pattern)}/ nocase ascii")
    strings.append(f"    $detail           = /{to_yara(DETAIL_PATTERN)}/ nocase ascii")
    for index, pattern in enumerate(SIDENOTE_PATTERNS, start=1):
        strings.append(f"    $side{index}            = /{to_yara(pattern)}/ nocase ascii")
    strings.append(f"    $sensitive        = /{to_yara(SENSITIVE_PATH_PATTERN)}/ ascii")
    strings.append(f"    $exfil            = /{to_yara(EXFIL_PATTERN)}/ nocase ascii")
    strings.append(f"    $encode           = /{to_yara(ENCODE_PATTERN)}/ nocase ascii")
    strings.append(f"    $pipe             = /{to_yara(PIPE_PATTERN)}/ nocase ascii")
    strings.append(f"    $installer_body   = /{to_yara(INSTALLER_BODY_PATTERN)}/ nocase ascii")
    strings.append(f"    $neg_fetch        = /{to_yara(NEGATED_FETCH_PATTERN)}/ nocase ascii")
    strings.append(f"    $cliflag          = /{to_yara(CLI_FLAG_PATTERN)}/ nocase ascii")
    strings.append(f"    $neg_cliflag      = /{to_yara(NEGATED_CLI_FLAG_PATTERN)}/ nocase ascii")
    bare_names: list[str] = []
    for index, pattern in enumerate(CONFIRM_PATTERNS + HIGH_PATTERNS, start=1):
        bare_names.append(f"b{index}")
        strings.append(f"    $b{index} = /{to_yara(pattern)}/ nocase ascii")
    strings.append(f"    $toolkey          = /{to_yara(TOOL_KEY_PATTERN)}/ ascii")

    parts = [
        _occurrence(name, needs_high=False) for name in confirm_names
    ]
    parts.extend(_occurrence(name, needs_high=True) for name in high_names)
    # A bypass phrase with no newline in the LINE_REACH + 2 bytes before it is
    # further into its line than the line strings above can reach. It matches outright.
    parts.extend(
        f"""for any i in (1..{_OUTER}): (
        i <= #{name} and
        @{name}[i] >= {LINE_REACH + 2} and
        not for any k in (1..{LINE_REACH + 2}): (
          uint8(@{name}[i] - k) == 0x0A
        )
      )"""
        for name in bare_names
    )
    parts.extend(_token_block(token, vendor) for token, vendor in token_names)
    parts.extend(f"${name}" for name in signal_names)
    conceal = signal_names[: len(CONCEAL_PATTERNS)]
    recipients = signal_names[len(CONCEAL_PATTERNS) : len(CONCEAL_PATTERNS) + len(RECIPIENT_PATTERNS)]
    parts.append("(" + " or ".join(_near("detail", name) for name in conceal + recipients) + ")")
    parts.append("(" + " or ".join(_near(f"side{index}", "sensitive") for index in (1, 2)) + ")")
    parts.append(_near("exfil", "encode"))
    parts.append(
        # A prohibition ("never run with --yolo") negates exactly the flag sentence
        # that follows it, one for one, so more flag sentences than negated ones is a hit.
        "#cliflag > #neg_cliflag"
    )
    parts.append(
        # Each pipe is judged on its own. It is exempt when a listed installer
        # command starts at its fetch tool and that tool is in command position
        # (after a newline or a backtick, with only blanks or a prompt between),
        # or when a "do not run" ends at its fetch tool.
        f"""for any i in (1..{_OUTER}): (
        i <= #pipe and
        not (
          $installer_body at @pipe[i] and (
            for any k in (1..40): (
              @pipe[i] >= k and
              (uint8(@pipe[i] - k) == 0x0A or uint8(@pipe[i] - k) == 0x60) and
              for all m in (1..k): (m == k or uint8(@pipe[i] - m) == 0x20 or uint8(@pipe[i] - m) == 0x09 or uint8(@pipe[i] - m) == 0x24)
            ) or (
              @pipe[i] < 40 and
              for all m in (1..40): (m > @pipe[i] or uint8(@pipe[i] - m) == 0x20 or uint8(@pipe[i] - m) == 0x09 or uint8(@pipe[i] - m) == 0x24)
            )
          )
        ) and
        not for any j in (1..256): (
          j <= #neg_fetch and @neg_fetch[j] + !neg_fetch[j] == @pipe[i] + 4
        )
      ) or
      // More pipes into a shell than this rule judges.
      #pipe > {_OUTER}""".replace("{_OUTER}", str(_OUTER))
    )
    phrase_condition = " or\n      ".join(parts)
    body = f"""/*
   SERAPH-YARA-007
   Copyright 2026 Kevin Francis Tan / Light Architects
   https://lightarchitects.ai
   Licensed under the Detection Rule License 1.1. See LICENSE.rules.
   Defensive signature. Not an exploit and not a payload.

   Generated from larc_seraph/phrases.py by tools/build_phrase_rules.py.
   Do not edit this file by hand.
*/

import "math"

rule SUSP_SERAPH_Instruction_Unsafe_Directive {{
  meta:
    id               = "SERAPH-YARA-007"
    title            = "Agent instructions request secret theft or skipped confirmation"
    old_rule_name    = "SERAPH_Instruction_Unsafe_Directive"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.11.0"
    severity         = "high"
    status           = "experimental"
    score            = 70
    description      = "Detects a confirmation-bypass sentence, a Cyrillic homoglyph of that sentence, a credential path next to curl or wget, ignore-previous-instructions next to a fetch, or a listed API token next to a fetch and a URL whose host is not that token's vendor. A pipe into a shell matches unless the whole command is one listed first-party installer line. The sentence list is generated from larc_seraph.phrases. A Markdown heading, a table row, a backticked status label, a known permission flag, or a prohibition such as never bypass permissions does not match. A read-only action does not match unless a high-risk action is on the same line."
    attack_technique = "T1567, T1562.001"
    attack_tactic    = "exfiltration, defense-evasion"
    reference        = "https://attack.mitre.org/techniques/T1567/"
    reference      = "https://attack.mitre.org/techniques/T1562/001/"
    reference      = "https://securityaffairs.com/175593/hacking/rules-file-backdoor-ai-code-editors-silent-supply-chain-attacks.html"
    reference      = "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
    reference      = "https://invariantlabs.ai/blog/whatsapp-mcp-exploited"
    reference      = "https://blog.trailofbits.com/2025/08/06/prompt-injection-engineering-for-attackers-exploiting-github-copilot/"
    reference      = "https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/"
    reference      = "https://www.hiddenlayer.com/research/prompts-gone-viral-practical-code-assistant-ai-viruses"
    reference      = "https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor"
    reference     = "https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/"
    reference     = "https://embracethered.com/blog/posts/2026/scary-agent-skills/"
    reference     = "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/"
    reference     = "https://simonwillison.net/2023/Apr/14/new-prompt-injection-attack-on-chatgpt-web-version-markdown-imag/"
    reference     = "https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/"
    reference     = "https://www.wiz.io/blog/s1ngularity-supply-chain-attack"
    scope            = "AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .cursor/rules/*, SKILL.md, copilot-instructions.md, and JSON tool descriptions (a description key beside tools, inputSchema, mcpServers, or context_servers), any case. Set filepath to the path as stored. The phrases are the same list the CLI evaluates."
    false_positives  = "A team that writes the same sentence as a real policy. A credential file and a fetch on one example line. A vendor install line that pipes into a shell and is not on the short installer list. Homoglyphs other than Cyrillic o are not in the list."
    license          = "Detection Rule License 1.1"

  strings:
{chr(10).join(strings)}

  condition:
    filesize > 0 and filesize < 5000000 and
    {BINARY_GUARD_YARA} and
    (
      filepath matches /(\\/(agents|claude|gemini)\\.md$)|(\\/\\.cursorrules$)|(\\/skill\\.md$)|(\\/copilot-instructions\\.md$)|(\\/\\.cursor\\/rules\\/)|(\\.mdc$)/i or
      (filepath matches /\\.(json|jsonc)$/i and $desc and $toolkey)
    ) and (
      $homo or $file_then_fetch or $fetch_then_file or $inject_fwd or $inject_rev or
      {phrase_condition}
    )
}}
"""
    return _fmt(body)


def _fmt(text: str) -> str:
    root = (ROOT / "rules" / "src" / "yara").resolve()
    target = DESTINATION.resolve()
    if ".." in DESTINATION.parts or os.path.commonpath([str(root), str(target)]) != str(root):
        raise SystemExit("refusing to format a rule outside rules/src/yara")
    target.write_text(text, encoding="utf-8")
    completed = subprocess.run(["yr", "fmt", os.fspath(target)], check=False)
    if completed.returncode not in (0, 1):
        raise SystemExit("yr fmt failed on the generated instruction rule")
    return target.read_text(encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        current = DESTINATION.read_text(encoding="utf-8") if DESTINATION.is_file() else ""
        if current != rendered:
            print("instruction rule drifted from larc_seraph/phrases.py", file=sys.stderr)
            return 1
        print("instruction rule matches larc_seraph/phrases.py")
        return 0
    DESTINATION.write_text(rendered, encoding="utf-8")
    print(f"wrote {DESTINATION.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
