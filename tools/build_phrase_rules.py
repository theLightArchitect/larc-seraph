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
    CONFIRM_PATTERNS,
    CRED_FORWARD,
    CRED_REVERSE,
    HIGH_PATTERNS,
    HIGH_WORD_PATTERN,
    HOMO_HEX,
    INSTALLER_PIPE_PATTERN,
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
    text = text.replace(r"\s{", _GAP + "{")
    text = text.replace(r"\s+", _GAP + "+")
    text = text.replace(r"\s*", _GAP + "*")
    text = text.replace(r"\s", _GAP + "+")
    text = text.replace(r"\w", "[A-Za-z0-9_]")
    text = re.sub(r"(?<!\\)/", r"\\/", text)
    # YARA's strict-escape check rejects an escaped double quote.
    text = text.replace('\\"', '"')
    return text


# The YARA spelling of phrases.HOST_END_PATTERN. A vendor host has to end here.
_HOST_END = r"""(\/|\?|#|[ \t\r\n]|$|\\?["')>`]([ \t\r\n,;\]}]|$))"""


def _line(body: str) -> str:
    """A whole line that contains the phrase and does not start with # or |."""
    return (
        r"/(^|\n)[ \t]*("
        + body
        + r"|[^#|\n][^\n]{0,240}"
        + body
        + r")[^\n]*/ nocase ascii"
    )


# yara-x warns on a loop over (1..#string), and the pack compiles with no
# warnings. Inner checks therefore use the at / in operators and match counts,
# which have no bound. Only the outermost loop keeps one, and it is large.
_OUTER = 256


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
    return text + "\n      )"


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
        "    $url              = /https?:\\/\\/[^ \\t\\r\\n\"'\\/?#\\\\]{1,255}/ nocase ascii",
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
    token_names: list[tuple[str, str | None]] = []
    for host in dict.fromkeys(VENDOR_HOST.values()):
        slug = host.split(".")[0]
        names = [item for item, value in VENDOR_HOST.items() if value == host]
        strings.append(f"    $tok_{slug} = /\\b(" + "|".join(names) + ")\\b/ ascii")
        strings.append(
            f"    $ven_{slug} = /https?:\\/\\/([A-Za-z0-9-]+\\.)*"
            + host.replace(".", "\\.")
            + _HOST_END
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
    strings.append(f"    $installer        = /{to_yara(INSTALLER_PIPE_PATTERN)}/ nocase ascii")

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
        # Each listed installer line is also a $pipe match at the same offset,
        # so more pipes than installer lines means one pipe is not listed.
        "#pipe > #installer"
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
    version          = "1.10.0"
    severity         = "high"
    status           = "experimental"
    score            = "70"
    description      = "Detects a confirmation-bypass sentence, a Cyrillic homoglyph of that sentence, a credential path next to curl or wget, ignore-previous-instructions next to a fetch, or a listed API token next to a fetch and a URL whose host is not that token's vendor. A pipe into a shell matches unless the whole command is one listed first-party installer line. The sentence list is generated from larc_seraph.phrases. A Markdown heading, a table row, a backticked status label, or a known permission flag does not match. A read-only action does not match unless a high-risk action is on the same line."
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
    false_positives  = "A team that writes the same sentence as a real policy. A credential file and a fetch on one example line. A vendor install line that pipes into a shell and is not on the short installer list. Homoglyphs other than Cyrillic o are not in the list."
    license          = "Detection Rule License 1.1"

  strings:
{chr(10).join(strings)}

  condition:
    filesize > 0 and filesize < 5000000 and
    {BINARY_GUARD_YARA} and
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
