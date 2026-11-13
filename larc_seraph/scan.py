"""Scan a file with the YARA pack, or one JSON event with the Sigma pack.

This is a local reviewer aid. It does not block, quarantine, or phone home.
A match is a lead for a person, not a verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import yara

from larc_seraph.eval import rule_matches
from larc_seraph.inventory import ROOT, load_sigma_rules
from larc_seraph.phrases import instruction_bypass


def read_scan_target(raw: str) -> bytes:
    """Read a file the operator named.

    Rejects a null byte and a `..` segment, then reads the resolved path.
    The scanner is meant to open files outside the repository. The check
    is against a path that walks up from the name the operator wrote.
    """
    if not raw or "\x00" in raw:
        raise ValueError("scan path is empty")
    candidate = Path(raw)
    if ".." in candidate.parts:
        raise ValueError("scan path must not contain ..")
    resolved = candidate.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"scan path is not a file: {resolved}")
    root = Path(resolved.anchor)
    if os.path.commonpath([str(root), str(resolved)]) != str(root):
        raise ValueError("scan path escapes its root")
    return resolved.read_bytes()


class NamedHit:
    """A scanner hit that did not come from libyara."""

    def __init__(self, rule: str) -> None:
        self.rule = rule


def _yara_paths(flavor: str) -> list[Path]:
    forge = sorted((ROOT / "rules" / "yara").glob("*.yar"))
    if flavor == "forge":
        return forge
    if flavor != "path":
        raise ValueError(f"unknown YARA flavor {flavor}")
    # Path-scoped twins plus the plist rules, which never read a path.
    paths = sorted((ROOT / "rules" / "path-scoped").glob("*.yar"))
    paths.extend(
        path for path in forge if path.name.startswith("launchplist_")
    )
    return paths


def compile_yara(flavor: str = "path") -> yara.Rules:
    """Compile one flavor.

    ``forge`` is rules/yara and must compile with no externals.
    ``path`` is the CLI set: path-scoped rules plus the plist rules.
    """
    paths = _yara_paths(flavor)
    if not paths:
        raise SystemExit(f"no YARA rules found for {flavor}")
    filepaths = {f"{flavor}-{path.stem}": str(path) for path in paths}
    if flavor == "forge":
        return yara.compile(filepaths=filepaths)
    return yara.compile(filepaths=filepaths, externals={"filepath": ""})


# Git will not store a fixture inside a directory named .git. The fixture
# tree uses .git-hooks, and this rewrite presents it as .git/hooks while
# keeping the case of that marker (.GIT-HOOKS becomes .GIT/HOOKS).
_GIT_HOOKS_MARKER = re.compile(r"\.git-hooks(?=/)", re.IGNORECASE)


def rule_filepath(path: str) -> str:
    """Normalize a path for rule scope.

    Backslashes become forward slashes. Case is preserved: the rules'
    filepath regexes are case-insensitive, and a scanner that lowercases
    the path hides bugs in those regexes.
    """
    text = path.replace("\\", "/")
    return _GIT_HOOKS_MARKER.sub(lambda match: match.group(0).replace("-", "/"), text)


def yara_match(
    rules: yara.Rules,
    path: str | None = None,
    data: bytes | None = None,
    filepath: str | None = None,
    *,
    use_filepath: bool = True,
    phrases: bool = True,
):
    """Match one file.

    Path-scoped rules read ``filepath``. Forge rules compile with no
    externals, so ``use_filepath`` must be false for that set.
    """

    if filepath is None:
        filepath = "" if path is None else rule_filepath(path)
    else:
        filepath = rule_filepath(filepath)
    options: dict[str, object] = {}
    if use_filepath:
        options["externals"] = {"filepath": filepath}
    if data is None:
        if path is None:
            raise ValueError("path or data is required")
        data = read_scan_target(path)
    hits = list(rules.match(data=data, **options))
    if not phrases:
        return hits
    names = {hit.rule for hit in hits}
    core = "SERAPH_Instruction_Unsafe_Directive"
    reported = f"{core}_Path" if use_filepath else core
    if reported not in names and core not in names and instruction_bypass(data, filepath, use_filepath=use_filepath):
        hits.append(NamedHit(reported))
    return hits


def scan_yara(targets: list[Path]) -> int:
    rules = compile_yara()
    matched = 0
    for target in targets:
        hits = yara_match(rules, path=str(target))
        if not hits:
            print(f"clean  {target}")
            continue
        matched += 1
        names = ", ".join(sorted(hit.rule for hit in hits))
        print(f"match  {target}")
        print(f"       {names}")
    return matched


def scan_sigma(targets: list[Path]) -> int:
    rules = [rule for rule, _path in load_sigma_rules()]
    matched = 0
    for target in targets:
        event = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            raise SystemExit(f"{target} is not a JSON object")
        names = sorted(rule.name or rule.title for rule in rules if rule_matches(rule, event))
        if not names:
            print(f"clean  {target}")
            continue
        matched += 1
        print(f"match  {target}")
        print(f"       {', '.join(names)}")
    return matched


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Scan files with the larc-seraph detection pack.")
    parser.add_argument("paths", nargs="+", type=Path, help="Files to scan")
    parser.add_argument(
        "--sigma",
        action="store_true",
        help="Treat each path as one normalized JSON event and evaluate the Sigma rules.",
    )
    args = parser.parse_args(argv)
    missing = [path for path in args.paths if not path.is_file()]
    if missing:
        raise SystemExit("not a file: " + ", ".join(str(path) for path in missing))
    count = scan_sigma(args.paths) if args.sigma else scan_yara(args.paths)
    print(f"{count} file(s) with a match, {len(args.paths)} scanned")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
