"""Build the Forge rules and the path-scoped twins from rules/src/yara.

rules/src/yara is the logic source. It still mentions the filepath external.
rules/yara is what YARA-Forge compiles, with that external removed.
rules/path-scoped keeps the external for the larc-seraph CLI.

Run with no arguments to write both trees. --check fails when the trees drift.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "rules" / "src" / "yara"
FORGE = ROOT / "rules" / "yara"
PATH = ROOT / "rules" / "path-scoped"

_RULE = re.compile(r"^rule\s+([A-Za-z0-9_]+)\s*\{", re.M)
_ID = re.compile(r'id\s*=\s*"(SERAPH-YARA-\d+)"')
_VERSION = re.compile(r'version\s*=\s*"(\d+)\.(\d+)\.(\d+)"')
_MCP_BLOCK = re.compile(
    r"\(\s*"
    r"\(filepath == \"\" and (?P<empty>.*?)\) or\s*"
    r"\(filepath != \"\" and filepath matches /\\\.\(json\|jsonc\|toml\|yml\|yaml\)"
    r"\(\\\.bak\|\\\.backup\[\^\\/\]\*\)\?\$/i and\s*"
    r"not filepath matches /\\\.\(md\|markdown\)\$/i\)\s*"
    r"\)",
    re.S,
)
_INSTRUCTION_BLOCK = re.compile(
    r"\(\s*"
    r"filepath matches /\(\\/\(agents\|claude\|gemini\)\\.md\$\)\|.*?"
    r"filepath matches /\\\.\(json\|jsonc\)\$/i and \$desc(?: and \$toolkey)?\)\s*"
    r"\)",
    re.S,
)
_BINARY_GUARD = re.compile(r"[ \t]*not for 8 i in \(0\.\.1023\):[^\n]*\) and\n")
_GIT_SAMPLE = re.compile(r"[ \t]*not filepath matches /\\\.sample\$/i and\n")
_GIT_PATH = re.compile(
    r"(?:[ \t]*//[^\n]*core\.hooksPath[^\n]*\n)?"
    r"[ \t]*\(filepath matches /\\\.git\\/hooks\\/[^\n]*\) and\n"
)

_MCP_GATE = """(
            (filepath == "" and (uint8(0) == 0x7B or $start_yaml or $start_toml)) or
            (filepath != "" and filepath matches /\\.(json|jsonc|toml|yml|yaml)(\\.bak|\\.backup[^\\/]*)?$/i and
                not filepath matches /\\.(md|markdown)$/i)
        )"""

_MCP_FORGE_GATE = """(
            uint8(0) == 0x7B or $start_yaml or $start_toml
        )"""

_MCP_GATE_LEGACY = """(
            (filepath == "" and uint8(0) == 0x7B) or
            (filepath != "" and filepath matches /\\.(json|jsonc|toml|yml|yaml)(\\.bak|\\.backup[^\\/]*)?$/i and
                not filepath matches /\\.(md|markdown)$/i)
        )"""

_MCP_FORGE_GATE_LEGACY = """(
            uint8(0) == 0x7B
        )"""

_INSTRUCTION_GATE = """(
            filepath matches /(\\/(agents|claude|gemini)\\.md$)|(\\/\\.cursorrules$)|(\\/skill\\.md$)|(\\/copilot-instructions\\.md$)|(\\/\\.cursor\\/rules\\/)/i or
            (filepath matches /\\.(json|jsonc)$/i and $desc)
        )"""

_INSTRUCTION_FORGE_GATE = """(
            any of ($mark_*) or
            ($desc and uint8(0) == 0x7B)
        )"""

_MARKERS = """
        $mark_phrase = /agent instructions/ nocase ascii
        $mark_agents = /AGENTS\\.md/ nocase ascii
        $mark_claude = /CLAUDE\\.md/ nocase ascii
        $mark_gemini = /GEMINI\\.md/ nocase ascii
        $mark_skill = /SKILL\\.md/ nocase ascii
        $mark_cursor = ".cursorrules" nocase ascii
        $mark_copilot = /copilot-instructions/ nocase ascii
        $mark_ruledir = ".cursor/rules/" nocase ascii
"""

_GIT_LINES = (
    "        not filepath matches /\\.sample$/i and\n",
    "        (filepath matches /\\.git\\/hooks\\/[^\\/]+$/i or filepath matches /\\.husky\\/[^\\/]+$/i) and\n",
)

_SCOPES = {
    "git_hook_suspicious_exec.yar": (
        "A shell or interpreter script that pipes a fetch or a decode into a shell, "
        "or posts a credential path. Git's sample banner (To enable this hook, rename this file) "
        "does not match. A hook that only runs a test suite does not match."
    ),
    "instruction_hidden_unicode.yar": (
        "Text with a Unicode tag or a bidi override (LRE, RLE, LRO, RLO). "
        "The portable rule does not require the file to mention its own name, because a real "
        "CLAUDE.md or .cursor/rules file often does not. The England, Scotland, and Wales flag emoji do not match. "
        "A file whose first kilobyte holds eight or more control bytes is treated as binary and skipped."
    ),
    "mcp_unpinned_package.yar": (
        "A JSON object at the start of the file (after an optional BOM or blank space), "
        "YAML that starts with mcpServers:, or TOML that starts with [mcp_servers or mcp_servers =. "
        "Markdown docs do not match. Allowlisted scopes are "
        "@modelcontextprotocol, @anthropic, and @github. A package token that itself contains @ and a "
        "version does not match. @latest is SERAPH-YARA-004."
    ),
    "instruction_unsafe_directive.yar": (
        "Text with an instruction marker or a JSON description that asks to skip confirmation, "
        "hides that sentence with a Cyrillic o, posts a credential path, or sends a listed token "
        "to a non-vendor host. The sentence list is generated from larc_seraph.phrases. "
        "A heading, a table row, a status label, or a known permission flag does not match."
    ),
}


# The Forge copies of these three rules have no path to consult, so they see far
# more files than the path-scoped twins. Their score and description say so.
_FORGE_SCORES = {
    "git_hook_suspicious_exec.yar": 45,
    "instruction_hidden_unicode.yar": 50,
    "instruction_unsafe_directive.yar": 50,
}
_FORGE_DESCRIPTIONS = {
    "git_hook_suspicious_exec.yar": (
        "Detects a shell or interpreter script that pipes a fetch into a shell, decodes into a shell, "
        "runs a fetch through command substitution, or sends a credential path to a network tool. "
        "In a Git hook this is the pattern from the cited incident. This rule has no path, "
        "so an installer script with the same line also matches. Treat a match as a lead."
    ),
    "instruction_hidden_unicode.yar": (
        "Detects Unicode tag characters, a bidi override or isolate, or a run of variation selectors "
        "in a text file. This rule has no path, so ordinary right-to-left text that uses an embedding "
        "mark also matches. The England, Scotland, and Wales flag emoji are ignored."
    ),
}
_FORGE_NOTES = {
    "instruction_unsafe_directive.yar": (
        "This rule has no path. Any text that names an instruction file is in scope, "
        "including source code that mentions CLAUDE.md."
    ),
}


def _forge_meta(name: str, text: str) -> str:
    if name in _FORGE_SCORES:
        text, count = re.subn(r"(score\s*=\s*)\d+", rf"\g<1>{_FORGE_SCORES[name]}", text, count=1)
        if count != 1:
            raise SystemExit(f"{name}: score not found")
    if name in _FORGE_DESCRIPTIONS:
        text = re.sub(
            r'description\s*=\s*"[^"]*"', f'description = "{_FORGE_DESCRIPTIONS[name]}"', text, count=1
        )
    if name in _FORGE_NOTES:
        text = _append_description(text, _FORGE_NOTES[name])
    return text


def _bump(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        major, minor, _patch = match.groups()
        return f'version = "{major}.{int(minor) + 1}.0"'

    return _VERSION.sub(repl, text, count=1)


def _drop_filepath_comments(text: str) -> str:
    kept: list[str] = []
    for line in text.splitlines(True):
        stripped = line.strip()
        if "filepath" in line and (
            stripped.startswith("*")
            or stripped.startswith("//")
            or "Scanners must" in line
            or stripped.startswith("An empty")
            or stripped.startswith("The regexes")
        ):
            continue
        kept.append(line)
    return "".join(kept)


def _replace_scope(name: str, text: str) -> str:
    if name not in _SCOPES and name.startswith("mcp_"):

        def repl(match: re.Match[str]) -> str:
            current = match.group(1)
            extra = (
                " The Forge rule has no path. It needs a JSON object at the start of the file "
                "(after an optional BOM or blank space), a top-level mcpServers: key, "
                "or an mcp_servers table. A JSONC file that opens with a comment, and Markdown, do not match."
            )
            if extra.strip() in current:
                return match.group(0)
            return f'scope = "{current}{extra}"'

        return re.sub(r'scope\s*=\s*"([^"]*)"', repl, text, count=1)
    if name not in _SCOPES:
        return text
    return re.sub(r'scope\s*=\s*"[^"]*"', f'scope = "{_SCOPES[name]}"', text, count=1)


def _append_description(text: str, sentence: str) -> str:
    def repl(match: re.Match[str]) -> str:
        current = match.group(1)
        if sentence in current:
            return match.group(0)
        return f'description = "{current} {sentence}"'

    return re.sub(r'description\s*=\s*"([^"]*)"', repl, text, count=1)


def forge_text(name: str, text: str) -> str:
    updated = _drop_filepath_comments(text)
    updated = _bump(updated)
    updated = _replace_scope(name, updated)
    updated = _forge_meta(name, updated)
    updated = _append_description(
        updated,
        "Content-only rule: it compiles with no externals.",
    )
    if name.startswith("mcp_"):
        match = _MCP_BLOCK.search(updated)
        if not match:
            raise SystemExit(f"{name}: MCP path gate not found")
        # The no-path branch of the source gate is the whole Forge gate.
        gate = match.group("empty").strip()
        if gate.startswith("(") and gate.endswith(")"):
            gate = gate[1:-1]
        updated = _MCP_BLOCK.sub(f"(\n      {gate}\n    )", updated, count=1)
    elif name.startswith("instruction_"):
        if not _INSTRUCTION_BLOCK.search(updated):
            raise SystemExit(f"{name}: instruction path gate not found")
        if name == "instruction_hidden_unicode.yar":
            # A real CLAUDE.md or .cursor/rules/*.mdc does not name itself.
            # The tag and bidi bytes are the signal. The path-scoped twin keeps the path gate.
            stripped, count = re.subn(
                _INSTRUCTION_BLOCK.pattern + r"\s*and\s*",
                "",
                updated,
                count=1,
                flags=re.S,
            )
            if count != 1:
                raise SystemExit(f"{name}: could not drop the self-name gate")
            updated = re.sub(r"(?m)^[ \t]*\$desc\s*=.*\n", "", stripped, count=1)
            updated = re.sub(r"(?m)^[ \t]*// A JSON file is a tool list[^\n]*\n[ \t]*\$toolkey\s*=.*\n", "", updated, count=1)
        else:
            updated = _INSTRUCTION_BLOCK.sub(
                "(\n      any of ($mark_*) or\n      ($desc and $toolkey and uint8(0) == 0x7B)\n    )",
                updated,
                count=1,
            )
            updated = updated.replace("\n  condition:\n", "\n" + _MARKERS + "\n  condition:\n", 1)
    elif name.startswith("git_hook_"):
        if not _GIT_SAMPLE.search(updated) or not _GIT_PATH.search(updated):
            raise SystemExit(f"{name}: git path gate not found")
        updated = _GIT_SAMPLE.sub("    not $sample_banner and\n", updated, count=1)
        updated = _GIT_PATH.sub("", updated, count=1)
        updated = updated.replace(
            "\n  condition:\n",
            '\n    $sample_banner = /To enable this hook, rename this file/ nocase ascii\n\n  condition:\n',
            1,
        )
    if "filepath" in updated:
        raise SystemExit(f"{name}: forge output still mentions filepath")
    return updated


def path_text(text: str) -> str:
    rule = _RULE.search(text)
    ident = _ID.search(text)
    if not rule or not ident:
        raise SystemExit("path source is missing a rule name or id")
    name = rule.group(1)
    updated = text.replace(f"rule {name}", f"rule {name}_Path", 1)
    updated = re.sub(r'(old_rule_name\s*=\s*")([^"]*)"', r'\1\2_Path"', updated, count=1)
    updated = updated.replace(ident.group(0), f'id = "{ident.group(1)}-PATH"', 1)
    updated = _bump(updated)
    updated = _append_description(
        updated,
        "Path-scoped variant. It requires the filepath external and is not for YARA-Forge.",
    )
    # The path is the evidence that this is an instruction file, so the binary
    # guard is dropped. A leading MZ or a few control bytes cannot switch the rule off.
    updated, _dropped = _BINARY_GUARD.subn("", updated, count=1)
    return updated


def build() -> dict[str, str]:
    if not SRC.is_dir():
        raise SystemExit(f"missing {SRC}")
    output: dict[str, str] = {}
    for path in sorted(SRC.glob("*.yar")):
        text = path.read_text(encoding="utf-8")
        if "filepath" not in text:
            output[f"rules/yara/{path.name}"] = text
            continue
        output[f"rules/yara/{path.name}"] = forge_text(path.name, text)
        output[f"rules/path-scoped/{path.name}"] = path_text(text)
    return output


def _fmt(text: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False, encoding="utf-8") as handle:
        handle.write(text)
        name = handle.name
    completed = subprocess.run(["yr", "fmt", name], check=False)
    if completed.returncode not in (0, 1):
        raise SystemExit(f"yr fmt failed on generated {name}")
    formatted = Path(name).read_text(encoding="utf-8")
    Path(name).unlink()
    return formatted


def write(output: dict[str, str]) -> None:
    FORGE.mkdir(parents=True, exist_ok=True)
    PATH.mkdir(parents=True, exist_ok=True)
    for relative, text in output.items():
        destination = ROOT / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(_fmt(text), encoding="utf-8")
    expected = {Path(relative).name for relative in output if relative.startswith("rules/path-scoped/")}
    for stale in PATH.glob("*.yar"):
        if stale.name not in expected:
            stale.unlink()


def check(output: dict[str, str]) -> int:
    drifted = []
    for relative, text in output.items():
        path = ROOT / relative
        if not path.is_file() or path.read_text(encoding="utf-8") != _fmt(text):
            drifted.append(relative)
    if drifted:
        print("rule flavors drifted from rules/src/yara:", file=sys.stderr)
        for relative in drifted:
            print(f"  {relative}", file=sys.stderr)
        return 1
    print("rule flavors match rules/src/yara")
    return 0


def _phrases(check: bool) -> int:
    command = [sys.executable, str(ROOT / "tools" / "build_phrase_rules.py")]
    if check:
        command.append("--check")
    return subprocess.run(command, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Forge and path-scoped YARA flavors.")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    phrase_status = _phrases(args.check)
    if phrase_status != 0:
        return phrase_status
    output = build()
    if args.check:
        return check(output)
    write(output)
    print(f"wrote {len(output)} rule files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
