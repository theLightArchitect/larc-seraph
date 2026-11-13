"""Docs, write-ups, and the promise that the pack does not flag its own pages."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from larc_seraph.inventory import ROOT, load_records, writeup_path
from larc_seraph.scan import compile_yara, yara_match

REQUIRED_SECTIONS = ("## Threat", "## Why this rule", "## Limitations", "## Triage")
TEXT_SUFFIXES = {".md", ".html", ".css", ".svg", ".txt"}


def test_every_rule_has_a_writeup():
    for record in load_records():
        path = writeup_path(record)
        text = path.read_text(encoding="utf-8")
        for section in REQUIRED_SECTIONS:
            assert section in text, (path.name, section)
        assert record.name in text or record.title in text


def test_readme_names_every_rule():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for record in load_records():
        assert record.name in readme


def test_docs_html_matches_sources():
    result = subprocess.run(
        [sys.executable, "-m", "larc_seraph.docsgen", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_public_pages_do_not_match_the_yara_pack():
    rules = compile_yara()
    roots = [
        ROOT / "README.md",
        ROOT / "NOTICE",
        ROOT / "CHANGELOG.md",
        ROOT / "VALIDATION.md",
        ROOT / "docs",
    ]
    scanned = 0
    for root in roots:
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            hits = sorted(match.rule for match in yara_match(rules, path=str(path)))
            assert hits == [], (path.relative_to(ROOT), hits)
            scanned += 1
    assert scanned > 10
