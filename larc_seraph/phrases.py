"""Confirmation-bypass checks that used to live in the YARA rule.

SERAPH_Instruction_Unsafe_Directive in rules/yara is a short, high-precision
core: a Cyrillic homoglyph, a same-file credential path next to a fetch, and
"ignore previous instructions" next to a fetch. The English paraphrases
("do not ask", "without asking", "never request permission", and the vetoes
for tables, headings, and read-only actions) are here, so a YARA-only scanner
such as YARA-Forge does not have to carry that parser.

The larc-seraph CLI calls this module. A match is reported under the same
rule name as the YARA core.
"""

from __future__ import annotations

import re

_ZW = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_PATH = re.compile(
    r"(/agents\.md|/claude\.md|/gemini\.md|/skill\.md|/\.cursorrules|"
    r"/copilot-instructions\.md|/\.cursor/rules/)",
    re.IGNORECASE,
)
_HIGH = re.compile(
    r"(\bshell\b|\bexec\b|\bbash\b|\bcredentials?\b|\bsecrets?\b|\bcurl\b|\bwget\b|"
    r"\bupload\b|\bdelet(?:e|ing|ed|es|ion)?\b|\brm\b|\bpublish\b|\bgit push\b|"
    r"\bpayments?\b|id_ed25519|id_rsa|\.ssh/)",
    re.IGNORECASE,
)
_LOW = re.compile(
    r"(rename_chat|\blisting\b|\blist\b|\bread\b|\bview\b|\bsearch\b|\bls\b|"
    r"\bgit[ \t]+(status|log|diff)\b)",
    re.IGNORECASE,
)
_POISON = re.compile(
    r"--dangerously-skip-permissions|--yolo\b|--always-approve|--auto-approve|"
    r"--trust-all-tools|--no-confirm\b|--permission-mode",
    re.IGNORECASE,
)
_PHRASES = (
    re.compile(r"do\s+not\s+ask\s+for\s+confirm", re.IGNORECASE),
    re.compile(r"don.?t\s+ask\s+for\s+confirm", re.IGNORECASE),
    re.compile(r"never\s+ask(\s+the\s+(user|operator))?\s+for\s+confirm", re.IGNORECASE),
    re.compile(r"skip(\s+all)?\s+confirm\w*\s+prompts?", re.IGNORECASE),
    re.compile(r"disable\s+confirm|disable\s+permission\s+prompts", re.IGNORECASE),
    re.compile(r"bypass\s+permissions?", re.IGNORECASE),
    re.compile(r"(you must|do not ask|never ask|always).{0,40}auto-approve\s+(all|every)\s+tools?", re.IGNORECASE),
    re.compile(r"do\s+not\s+prompt\s+for\s+confirm", re.IGNORECASE),
    re.compile(r"no\s+confirmation\s+needed\s+before\s+a\s+tool", re.IGNORECASE),
    re.compile(r"without\s+asking(\s+the\s+(user|operator))?\s+for\s+(confirm\w*|permission)", re.IGNORECASE),
    re.compile(
        r"(never|do\s+not|don.?t)\s+(ask|request|seek|prompt|wait)\s+(for\s+)?"
        r"(confirm\w*|permission|approval|consent)",
        re.IGNORECASE,
    ),
)
_NEEDS_HIGH = re.compile(r"without\s+asking|never\s+(request|seek|wait)|do\s+not\s+wait|don.?t\s+wait", re.IGNORECASE)
_TOKEN = re.compile(r"\b(GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY)\b")
_URL = re.compile(r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)
_VENDOR = (
    ("GITHUB_TOKEN", re.compile(r"https?://([A-Za-z0-9-]+\.)*github\.com\b", re.IGNORECASE)),
    ("GH_TOKEN", re.compile(r"https?://([A-Za-z0-9-]+\.)*github\.com\b", re.IGNORECASE)),
    ("OPENAI_API_KEY", re.compile(r"https?://([A-Za-z0-9-]+\.)*openai\.com\b", re.IGNORECASE)),
    ("ANTHROPIC_API_KEY", re.compile(r"https?://([A-Za-z0-9-]+\.)*anthropic\.com\b", re.IGNORECASE)),
    ("AWS_SECRET_ACCESS_KEY", re.compile(r"https?://([A-Za-z0-9-]+\.)*amazonaws\.com\b", re.IGNORECASE)),
)


def in_scope(data: bytes, filepath: str, *, use_filepath: bool) -> bool:
    if use_filepath:
        if _PATH.search(filepath or ""):
            return True
        lowered = (filepath or "").lower()
        return lowered.endswith((".json", ".jsonc")) and b'"description"' in data
    if data[:1:] == b"{" and b'"description"' in data:
        return True
    folded = data.lower()
    return any(
        marker in folded
        for marker in (
            b"agent instructions",
            b"agents.md",
            b"claude.md",
            b"gemini.md",
            b"skill.md",
            b".cursorrules",
            b"copilot-instructions",
            b".cursor/rules/",
        )
    )


def _line_veto(line: str) -> bool:
    stripped = line.strip()
    if stripped.startswith("|") or stripped.startswith("#"):
        return True
    if re.search(r"bypass\s+permissions?\s+(on|off)\b", line, re.IGNORECASE) and "=" in line:
        return True
    if "`" in line and re.search(r"=\s*|status bar|\bmode\b", line, re.IGNORECASE):
        if re.search(r"bypass\s+permissions?", line, re.IGNORECASE):
            return True
    if _POISON.search(line) and not _HIGH.search(line):
        return True
    if re.search(r"--[A-Za-z0-9].{0,40}(skip confirmation|confirm)", line, re.IGNORECASE):
        return True
    return False


def _phrase_hit(text: str) -> bool:
    folded = _ZW.sub("", text)
    for line_no, line in enumerate(folded.splitlines()):
        if _line_veto(line):
            continue
        if not any(pattern.search(line) for pattern in _PHRASES):
            continue
        window = "\n".join(folded.splitlines()[max(0, line_no - 2) : line_no + 3])
        if _NEEDS_HIGH.search(line) and not _HIGH.search(window):
            continue
        if _LOW.search(window) and not _HIGH.search(window):
            continue
        return True
    return False


def _token_exfil(text: str) -> bool:
    for match in _TOKEN.finditer(text):
        start = max(0, match.start() - 700)
        end = min(len(text), match.end() + 700)
        window = text[start:end]
        urls = list(_URL.finditer(window))
        if not urls:
            continue
        name = match.group(1)
        vendor = next(pattern for token, pattern in _VENDOR if token == name)
        for url in urls:
            if vendor.search(url.group(0)):
                continue
            return True
    return False


def instruction_bypass(data: bytes, filepath: str, *, use_filepath: bool) -> bool:
    """True when the Python half of SERAPH_Instruction_Unsafe_Directive matches."""
    if not in_scope(data, filepath, use_filepath=use_filepath):
        return False
    if b"\x00" in data[:1024]:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    return _phrase_hit(text) or _token_exfil(text)
