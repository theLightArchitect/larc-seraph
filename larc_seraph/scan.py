"""Scan a file with the YARA pack, or one JSON event with the Sigma pack.

This is a local reviewer aid. It does not block, quarantine, or phone home.
A match is a lead for a person, not a verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yara

from larc_seraph.eval import rule_matches
from larc_seraph.inventory import ROOT, load_sigma_rules


def compile_yara() -> yara.Rules:
    paths = sorted((ROOT / "rules" / "yara").glob("*.yar"))
    if not paths:
        raise SystemExit("no YARA rules found")
    return yara.compile(filepaths={path.stem: str(path) for path in paths})


def scan_yara(targets: list[Path]) -> int:
    rules = compile_yara()
    matched = 0
    for target in targets:
        hits = rules.match(str(target))
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
