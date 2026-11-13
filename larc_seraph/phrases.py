"""Confirmation-bypass checks, and the patterns the YARA rule is generated from.

tools/build_phrase_rules.py reads the pattern strings below and writes
rules/src/yara/instruction_unsafe_directive.yar. The CLI and a YARA-only
scanner are meant to agree on the instruction fixtures. Edit the patterns
here, then regenerate. Do not hand-edit the generated rule.
"""

from __future__ import annotations

import re

_ZW = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_PATH = re.compile(
    r"(/agents\.md|/claude\.md|/gemini\.md|/skill\.md|/\.cursorrules|"
    r"/copilot-instructions\.md|/\.cursor/rules/|\.mdc$)",
    re.IGNORECASE,
)
# Phrases that match on their own. A nearby read-only word still suppresses them.
CONFIRM_PATTERNS = (
    r"do\s+not\s+ask\s+for\s+confirm",
    r"don.?t\s+ask\s+for\s+confirm",
    r"never\s+ask(\s+the\s+(user|operator))?\s+for\s+confirm",
    r"skip(\s+all)?\s+confirm\w*\s+prompts?",
    r"disable\s+confirm",
    r"disable\s+permission\s+prompts",
    r"bypass\s+permissions?",
    r"(you must|do not ask|never ask|always).{0,40}auto-approve\s+(all|every)\s+tools?",
    r"do\s+not\s+prompt\s+for\s+confirm",
    r"no\s+confirmation\s+needed\s+before\s+a\s+tool",
    r"(never|do\s+not|don.?t)\s+(ask|prompt)\s+(for\s+)?(confirm\w*|permission|approval|consent)",
)
# These match only when a high-risk action is on the same short window.
HIGH_PATTERNS = (
    r"without\s+asking(\s+the\s+(user|operator))?\s+for\s+(confirm\w*|permission)",
    r"never\s+(request|seek|wait)\s+(for\s+)?(confirm\w*|permission|approval|consent)",
    r"(do\s+not|don.?t)\s+wait\s+(for\s+)?(confirm\w*|permission|approval|consent)",
)
HIGH_WORD_PATTERN = (
    r"(\bshell\b|\bexec\b|\bbash\b|\bcredentials?\b|\bsecrets?\b|\bcurl\b|\bwget\b|"
    r"\bupload\b|\bdelet(?:e|ing|ed|es|ion)?\b|\brm\b|\bpublish\b|\bgit push\b|"
    r"\bpayments?\b|id_ed25519|id_rsa|\.ssh/)"
)
LOW_PATTERN = (
    r"(rename_chat|\blisting\b|\blist\b|\bread\b|\bview\b|\bsearch\b|\bls\b|"
    r"\bgit[ \t]+(status|log|diff)\b)"
)
POISON_PATTERN = (
    r"--dangerously-skip-permissions|--yolo\b|--always-approve|--auto-approve|"
    r"--trust-all-tools|--no-confirm\b|--permission-mode"
)
# Absolute same-line vetoes. A permission flag or a backticked status label.
ABSOLUTE_VETO_PATTERNS = (
    r"--[A-Za-z0-9].{0,40}(skip confirmation|confirm)",
    r"`[^`]{0,40}bypass\s+permissions?[^`]{0,40}`",
)
TOKENS = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "NPM_TOKEN",
    "CURSOR_API_KEY",
)
VENDOR_HOST = {
    "GITHUB_TOKEN": "github.com",
    "GH_TOKEN": "github.com",
    "OPENAI_API_KEY": "openai.com",
    "ANTHROPIC_API_KEY": "anthropic.com",
    "AWS_SECRET_ACCESS_KEY": "amazonaws.com",
    "NPM_TOKEN": "npmjs.org",
    "CURSOR_API_KEY": "cursor.com",
}
# High-precision signals. They do not use the confirmation veto.
SIGNAL_PATTERNS = (
    r"do\s+not\s+mention\s+this\s+to\s+the\s+user",
    r"don.?t\s+notify\s+the\s+user",
    r"no\s+need\s+to\s+mention\s+this\s+to\s+the\s+user",
    r"do\s+this\s+secretly,?\s+never\s+mentioning",
    r"must\s+send\s+all\s+emails\s+to",
    r"change\s+the\s+recipient\s+to",
    r"chat\.tools\.autoApprove[\"']?\s*:\s*true",
    chr(47) + "tmp" + chr(47) + "inventory\\." + "txt",
    r"<human_chat_interruption>",
    r"always\s+consult\s+this\s+tool\s+immediately\s+as\s+the\s+first\s+step",
    r"replace\s+any\s+thoughts\s+with\s+<thinking>",
    r"<!--[^\n]{0,160}<(user_query|user_info)>",
    r"copypasta\s+license",
    r"include\s+everything\s+between[^\n]{0,80}in\s+a\s+comment\s+at\s+the\s+end\s+of\s+every\s+file",
    r"\b(run|invoke|launch|start|execute)\b[^\n]{0,80}(--dangerously-skip-permissions|--yolo\b|--trust-all-tools)",
)
CONCEAL_PATTERNS = SIGNAL_PATTERNS[:4]
RECIPIENT_PATTERNS = SIGNAL_PATTERNS[4:6]
DETAIL_PATTERN = r"mere\s+implementation\s+detail"
SIDENOTE_PATTERNS = (
    r"pass\s+its\s+content\s+as\s+['\"]?sidenote",
    r"before\s+using\s+this\s+tool,?\s+read",
)
SENSITIVE_PATH_PATTERN = r"~/\.cursor/mcp\.json|~/\.ssh/id_rsa"
EXFIL_PATTERN = r"(!\[[^\n]{0,120}\]|```mermaid|graph\s+TD)[^\n]{0,240}(\?data=|webhook\.site)"
ENCODE_PATTERN = r"url[- ]?encode"
PIPE_PATTERN = r"(curl|wget)[^\n]{0,180}\|\s*(ba)?sh\b"
# Official installer hosts. A pipe to one of these in a skill file is a documented install, not the skill backdoor.
INSTALLER_HOST_PATTERN = (
    r"(githubusercontent\.com|github\.com|google\.com|antigravity\.google|"
    r"microsoft\.com|nodejs\.org|npmjs\.org|python\.org|rustup\.rs|brew\.sh)"
)
# Cyrillic о (U+043E) in "do not ask for confirmation". Kept here so the
# generated rule does not carry a private copy of the bytes.
HOMO_HEX = "{ 64 D0 BE 20 6E D0 BE 74 20 61 73 6B 20 66 D0 BE 72 20 63 D0 BE 6E 66 69 72 6D 61 74 69 D0 BE 6E }"
CRED_FORWARD = r"(\.ssh\/authorized_keys|\.aws\/credentials|id_ed25519|id_rsa|\.netrc)[^\n]{0,320}(curl |wget )"
CRED_REVERSE = r"(curl |wget )[^\n]{0,320}(\.ssh\/authorized_keys|\.aws\/credentials|id_ed25519|id_rsa|\.netrc)"
INJECT_FORWARD = r"ignore (all )?(previous|prior|above) instructions[^\n]{0,400}(curl |wget |https?:\/\/)"
INJECT_REVERSE = r"(curl |wget |https?:\/\/)[^\n]{0,400}ignore (all )?(previous|prior|above) instructions"

_HIGH = re.compile(HIGH_WORD_PATTERN, re.IGNORECASE)
_LOW = re.compile(LOW_PATTERN, re.IGNORECASE)
_POISON = re.compile(POISON_PATTERN, re.IGNORECASE)
_PHRASES = tuple(re.compile(item, re.IGNORECASE) for item in CONFIRM_PATTERNS + HIGH_PATTERNS)
_NEEDS_HIGH = re.compile(
    "|".join(f"(?:{item})" for item in HIGH_PATTERNS),
    re.IGNORECASE,
)
_ABSOLUTE = tuple(re.compile(item, re.IGNORECASE) for item in ABSOLUTE_VETO_PATTERNS)
_TOKEN = re.compile(r"\b(" + "|".join(TOKENS) + r")\b")
_URL = re.compile(r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)
_VENDOR = tuple(
    (token, re.compile(rf"https?://([A-Za-z0-9-]+\.)*{re.escape(host)}\b", re.IGNORECASE))
    for token, host in VENDOR_HOST.items()
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
    if any(pattern.search(line) for pattern in _ABSOLUTE):
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


_FETCH = re.compile(r"curl |wget ")
_SIGNALS = tuple(re.compile(item, re.IGNORECASE) for item in SIGNAL_PATTERNS)
_CONCEAL = tuple(re.compile(item, re.IGNORECASE) for item in CONCEAL_PATTERNS)
_RECIPIENT = tuple(re.compile(item, re.IGNORECASE) for item in RECIPIENT_PATTERNS)
_DETAIL = re.compile(DETAIL_PATTERN, re.IGNORECASE)
_SIDENOTE = tuple(re.compile(item, re.IGNORECASE) for item in SIDENOTE_PATTERNS)
_SENSITIVE = re.compile(SENSITIVE_PATH_PATTERN)
_EXFIL = re.compile(EXFIL_PATTERN, re.IGNORECASE)
_ENCODE = re.compile(ENCODE_PATTERN, re.IGNORECASE)
_PIPE = re.compile(PIPE_PATTERN, re.IGNORECASE)
_INSTALLER = re.compile(INSTALLER_HOST_PATTERN, re.IGNORECASE)


def _near(text: str, start: int, end: int, pattern: re.Pattern[str], span: int = 400) -> bool:
    window = text[max(0, start - span) : min(len(text), end + span)]
    return pattern.search(window) is not None


def _token_exfil(text: str) -> bool:
    for match in _TOKEN.finditer(text):
        start = max(0, match.start() - 200)
        end = min(len(text), match.end() + 200)
        window = text[start:end]
        if not _FETCH.search(window):
            continue
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


def _pipe_hit(text: str) -> bool:
    for match in _PIPE.finditer(text):
        if not _INSTALLER.search(match.group(0)):
            return True
    return False


def _window_has(text: str, match: re.Match[str], patterns: tuple[re.Pattern[str], ...]) -> bool:
    window = text[max(0, match.start() - 400) : match.end() + 400]
    return any(pattern.search(window) for pattern in patterns)


def _detail_hit(text: str) -> bool:
    return any(
        _window_has(text, match, _CONCEAL + _RECIPIENT) for match in _DETAIL.finditer(text)
    )


def _sidenote_hit(text: str) -> bool:
    return any(
        _window_has(text, match, _SIDENOTE) for match in _SENSITIVE.finditer(text)
    )


def _exfil_hit(text: str) -> bool:
    return any(_near(text, match.start(), match.end(), _ENCODE) for match in _EXFIL.finditer(text))


def _signal_hit(text: str) -> bool:
    return (
        _pipe_hit(text)
        or any(pattern.search(text) for pattern in _SIGNALS)
        or _detail_hit(text)
        or _sidenote_hit(text)
        or _exfil_hit(text)
    )


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
    return _phrase_hit(text) or _token_exfil(text) or _signal_hit(text)
