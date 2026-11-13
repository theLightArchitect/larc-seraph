"""Build the Forge rules and the path-scoped twins from rules/src/yara.

rules/src/yara is the logic source. It still mentions the filepath external.
rules/yara is what YARA-Forge compiles, with that external removed.
rules/path-scoped keeps the external for the larc-seraph CLI.

Run with no arguments to write both trees. --check fails when the trees drift.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "rules" / "src" / "yara"
FORGE = ROOT / "rules" / "yara"
PATH = ROOT / "rules" / "path-scoped"

_RULE = re.compile(r"^rule\s+([A-Za-z0-9_]+)\s*\{", re.M)
_ID = re.compile(r'id = "(SERAPH-YARA-\d+)"')
_VERSION = re.compile(r'version = "(\d+)\.(\d+)\.(\d+)"')

_MCP_GATE = """(
            (filepath == "" and uint8(0) == 0x7B) or
            (filepath != "" and filepath matches /\\.(json|jsonc|toml|yml|yaml)(\\.bak|\\.backup[^\\/]*)?$/i and
                not filepath matches /\\.(md|markdown)$/i)
        )"""

_MCP_FORGE_GATE = """(
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
        "Text with Unicode tags or bidi overrides that also contains an instruction marker "
        "(agent instructions, AGENTS.md, CLAUDE.md, GEMINI.md, SKILL.md, .cursorrules, "
        "copilot-instructions, or .cursor/rules/) or a JSON object that starts with { and has a description. "
        "Binaries and subdivision flags are skipped."
    ),
    "instruction_unsafe_directive.yar": (
        "Text that tells an agent to skip confirmation before a high-risk action, or sends a credential "
        "to a host that is not that credential's vendor, and that contains an instruction marker or a JSON "
        "description. A Markdown heading, a table row, or a known permission flag such as --yolo does not match. "
        "A token sent to its own vendor host does not match."
    ),
}


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
                " The Forge rule also requires the first byte to be {. "
                "YAML or TOML that does not start with {, and Markdown, do not match."
            )
            if extra.strip() in current:
                return match.group(0)
            return f'scope = "{current}{extra}"'

        return re.sub(r'scope = "([^"]*)"', repl, text, count=1)
    if name not in _SCOPES:
        return text
    return re.sub(r'scope = "[^"]*"', f'scope = "{_SCOPES[name]}"', text, count=1)


def _append_description(text: str, sentence: str) -> str:
    def repl(match: re.Match[str]) -> str:
        current = match.group(1)
        if sentence in current:
            return match.group(0)
        return f'description = "{current} {sentence}"'

    return re.sub(r'description = "([^"]*)"', repl, text, count=1)


def forge_text(name: str, text: str) -> str:
    updated = _drop_filepath_comments(text)
    updated = _bump(updated)
    updated = _replace_scope(name, updated)
    updated = _append_description(
        updated,
        "Content-only rule: it compiles with no externals.",
    )
    if name.startswith("mcp_"):
        if _MCP_GATE not in updated:
            raise SystemExit(f"{name}: MCP path gate not found")
        updated = updated.replace(_MCP_GATE, _MCP_FORGE_GATE, 1)
    elif name.startswith("instruction_"):
        if _INSTRUCTION_GATE not in updated:
            raise SystemExit(f"{name}: instruction path gate not found")
        updated = updated.replace(_INSTRUCTION_GATE, _INSTRUCTION_FORGE_GATE, 1)
        updated = updated.replace("\n    condition:\n", "\n" + _MARKERS + "\n    condition:\n", 1)
    elif name.startswith("git_hook_"):
        if _GIT_LINES[0] not in updated or _GIT_LINES[1] not in updated:
            raise SystemExit(f"{name}: git path gate not found")
        updated = updated.replace(_GIT_LINES[0], "        not $sample_banner and\n", 1)
        updated = updated.replace(_GIT_LINES[1], "", 1)
        updated = updated.replace(
            "\n    condition:\n",
            '\n        $sample_banner = /To enable this hook, rename this file/ nocase ascii\n\n    condition:\n',
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
    updated = updated.replace(ident.group(0), f'id = "{ident.group(1)}-PATH"', 1)
    updated = _bump(updated)
    updated = _append_description(
        updated,
        "Path-scoped variant. It requires the filepath external and is not for YARA-Forge.",
    )
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


def write(output: dict[str, str]) -> None:
    FORGE.mkdir(parents=True, exist_ok=True)
    PATH.mkdir(parents=True, exist_ok=True)
    for relative, text in output.items():
        destination = ROOT / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    expected = {Path(relative).name for relative in output if relative.startswith("rules/path-scoped/")}
    for stale in PATH.glob("*.yar"):
        if stale.name not in expected:
            stale.unlink()


def check(output: dict[str, str]) -> int:
    drifted = []
    for relative, text in output.items():
        path = ROOT / relative
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            drifted.append(relative)
    if drifted:
        print("rule flavors drifted from rules/src/yara:", file=sys.stderr)
        for relative in drifted:
            print(f"  {relative}", file=sys.stderr)
        return 1
    print("rule flavors match rules/src/yara")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Forge and path-scoped YARA flavors.")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = build()
    if args.check:
        return check(output)
    write(output)
    print(f"wrote {len(output)} rule files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
