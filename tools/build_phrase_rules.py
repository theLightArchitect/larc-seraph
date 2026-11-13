"""Generate the instruction YARA rule from larc_seraph.phrases.

The pattern strings in that module are the source. This writes
rules/src/yara/instruction_unsafe_directive.yar. --check fails when the
file drifts. tools/build_rule_flavors.py then writes both flavors.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from larc_seraph.phrases import (  # noqa: E402
    ABSOLUTE_VETO_PATTERNS,
    CONFIRM_PATTERNS,
    CRED_FORWARD,
    CRED_REVERSE,
    HIGH_PATTERNS,
    HIGH_WORD_PATTERN,
    HOMO_HEX,
    INSTALLER_HOST_PATTERN,
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

# Spaces, tabs, or one of the zero-width bytes the phrase module strips.
_GAP = r"([ \t]|\xE2\x80\x8B|\xE2\x80\x8C|\xE2\x80\x8D|\xE2\x81\xA0|\xEF\xBB\xBF)"


def to_yara(pattern: str) -> str:
    """Translate one phrase-module regex into a YARA regex body."""
    text = pattern.replace("(?:", "(")
    text = re.sub(r"(?<!\\)\.", r"[^\\n]", text)
    text = text.replace(r"\s+", _GAP + "+")
    text = text.replace(r"\s*", _GAP + "*")
    text = text.replace(r"\s", _GAP + "+")
    text = text.replace(r"\w", "[A-Za-z0-9_]")
    text = re.sub(r"(?<!\\)/", r"\\/", text)
    return text


def _line(body: str) -> str:
    """A whole line that contains the phrase and does not start with # or |."""
    return (
        r"/(^|\n)[ \t]*("
        + body
        + r"|[^#|\n][^\n]{0,240}"
        + body
        + r")[^\n]*/ nocase ascii"
    )


def _occurrence(name: str, *, needs_high: bool) -> str:
    window = (
        f"@soft[j] >= @{name}[i] and @soft[j] < @{name}[i] + !{name}[i]"
    )
    high = f"@high[j] >= @{name}[i] and @high[j] < @{name}[i] + !{name}[i]"
    bad = f"@bad[j] >= @{name}[i] and @bad[j] < @{name}[i] + !{name}[i]"
    text = f"""for any i in (1..8): (
        i <= #{name} and
        not for any j in (1..8): (
          j <= #bad and {bad}
        ) and not (
          for any j in (1..8): (
            j <= #soft and {window}
          ) and not for any j in (1..8): (
            j <= #high and {high}
          )
        )"""
    if needs_high:
        text += f""" and
        for any j in (1..8): (
          j <= #high and {high}
        )"""
    return text + "\n      )"


def _token_block(name: str, vendor: str) -> str:
    return f"""for any i in (1..8): (
        i <= #{name} and
        for any j in (1..8): (
          j <= #url and
          @url[j] + 200 >= @{name}[i] and
          @{name}[i] + 200 >= @url[j] and
          not for any k in (1..8): (
            k <= #{vendor} and @{vendor}[k] == @url[j]
          ) and
          for any f in (1..8): (
            f <= #fetch and
            @fetch[f] + 200 >= @{name}[i] and
            @{name}[i] + 200 >= @fetch[f]
          )
        )
      )"""


def _near(left: str, right: str) -> str:
    return f"""for any i in (1..8): (
        i <= #{left} and
        for any j in (1..8): (
          j <= #{right} and
          @{right}[j] + 400 >= @{left}[i] and
          @{left}[i] + 400 >= @{right}[j]
        )
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
        "    $url              = /https?:\\/\\/[A-Za-z0-9.-]{1,80}\\.[A-Za-z]{2,}/ nocase ascii",
        "    $fetch            = /(curl |wget )/ nocase ascii",
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
    hosts: dict[str, str] = {}
    for token in TOKENS:
        host = VENDOR_HOST[token]
        hosts.setdefault(host, token)
    token_names: list[tuple[str, str]] = []
    for host, token in hosts.items():
        slug = host.split(".")[0]
        names = [item for item, value in VENDOR_HOST.items() if value == host]
        token_name = f"tok_{slug}"
        vendor_name = f"ven_{slug}"
        strings.append(
            "    $"
            + token_name
            + " = /\\b("
            + "|".join(names)
            + ")\\b/ ascii"
        )
        strings.append(
            "    $"
            + vendor_name
            + " = /https?:\\/\\/([A-Za-z0-9-]+\\.)*"
            + host.replace(".", "\\.")
            + "/ nocase ascii"
        )
        token_names.append((token_name, vendor_name))
        del token

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
    strings.append(f"    $installer        = /{to_yara(INSTALLER_HOST_PATTERN)}/ nocase ascii")

    parts = [
        _occurrence(name, needs_high=False) for name in confirm_names
    ]
    parts.extend(_occurrence(name, needs_high=True) for name in high_names)
    parts.extend(_token_block(token, vendor) for token, vendor in token_names)
    parts.extend(f"${name}" for name in signal_names)
    conceal = signal_names[: len(CONCEAL_PATTERNS)]
    recipients = signal_names[len(CONCEAL_PATTERNS) : len(CONCEAL_PATTERNS) + len(RECIPIENT_PATTERNS)]
    parts.append("(" + " or ".join(_near("detail", name) for name in conceal + recipients) + ")")
    parts.append("(" + " or ".join(_near(f"side{index}", "sensitive") for index in (1, 2)) + ")")
    parts.append(_near("exfil", "encode"))
    parts.append(
        """for any i in (1..8): (
        i <= #pipe and
        not for any j in (1..8): (
          j <= #installer and @installer[j] >= @pipe[i] and @installer[j] < @pipe[i] + !pipe[i]
        )
      )"""
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

rule SERAPH_Instruction_Unsafe_Directive {{
  meta:
    id               = "SERAPH-YARA-007"
    title            = "Agent instructions request secret theft or skipped confirmation"
    author           = "Kevin Francis Tan"
    organization     = "Light Architects"
    author_url       = "https://lightarchitects.ai"
    date             = "2026-11-13"
    modified         = "2026-11-13"
    version          = "1.9.0"
    severity         = "high"
    status           = "experimental"
    score            = "70"
    description      = "Detects a confirmation-bypass sentence, a Cyrillic homoglyph of that sentence, a credential path next to curl or wget, ignore-previous-instructions next to a fetch, or a listed API token next to a URL that is not that token's vendor. The sentence list is generated from larc_seraph.phrases. A Markdown heading, a table row, a backticked status label, or a known permission flag does not match. A read-only action does not match unless a high-risk action is on the same line."
    attack_technique = "T1567, T1562.001"
    attack_tactic    = "exfiltration, defense-evasion"
    reference        = "https://attack.mitre.org/techniques/T1567/"
    reference_2      = "https://attack.mitre.org/techniques/T1562/001/"
    reference_3      = "https://securityaffairs.com/175593/hacking/rules-file-backdoor-ai-code-editors-silent-supply-chain-attacks.html"
    reference_4      = "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
    reference_5      = "https://invariantlabs.ai/blog/whatsapp-mcp-exploited"
    reference_6      = "https://blog.trailofbits.com/2025/08/06/prompt-injection-engineering-for-attackers-exploiting-github-copilot/"
    reference_7      = "https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/"
    reference_8      = "https://www.hiddenlayer.com/research/prompts-gone-viral-practical-code-assistant-ai-viruses"
    reference_9      = "https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor"
    reference_10     = "https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/"
    reference_11     = "https://embracethered.com/blog/posts/2026/scary-agent-skills/"
    reference_12     = "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/"
    reference_13     = "https://simonwillison.net/2023/Apr/14/new-prompt-injection-attack-on-chatgpt-web-version-markdown-imag/"
    reference_14     = "https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/"
    reference_15     = "https://www.wiz.io/blog/s1ngularity-supply-chain-attack"
    scope            = "AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .cursor/rules/*, SKILL.md, copilot-instructions.md, and JSON tool descriptions, any case. Set filepath to the path as stored. The phrases are the same list the CLI evaluates."
    false_positives  = "A team that writes the same sentence as a real policy. A credential file and a fetch on one example line. Homoglyphs other than Cyrillic o are not in the list."
    license          = "Detection Rule License 1.1"

  strings:
{chr(10).join(strings)}

  condition:
    filesize > 0 and filesize < 5000000 and
    not (uint32(0) == 0x464c457f) and
    not (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcffaedfe or uint32(0) == 0xbebafeca) and
    not (uint16(0) == 0x5a4d) and
    not (uint32(0) == 0x04034b50) and
    not (uint16(0) == 0x8b1f) and
    not for any i in (0..math.min(1023, filesize - 1)): (uint8(i) == 0) and
    (
      filepath matches /(\\/(agents|claude|gemini)\\.md$)|(\\/\\.cursorrules$)|(\\/skill\\.md$)|(\\/copilot-instructions\\.md$)|(\\/\\.cursor\\/rules\\/)|(\\.mdc$)/i or
      (filepath matches /\\.(json|jsonc)$/i and $desc)
    ) and (
      $homo or $file_then_fetch or $fetch_then_file or $inject_fwd or $inject_rev or
      {phrase_condition}
    )
}}
"""
    return _fmt(body)


def _fmt(text: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False, encoding="utf-8") as handle:
        handle.write(text)
        name = handle.name
    completed = subprocess.run(["yr", "fmt", name], check=False)
    if completed.returncode not in (0, 1):
        raise SystemExit("yr fmt failed on the generated instruction rule")
    formatted = Path(name).read_text(encoding="utf-8")
    Path(name).unlink()
    return formatted


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
