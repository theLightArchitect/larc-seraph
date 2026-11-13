"""Fixture truth table, metadata, and Sigma specification checks."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
import yara

from larc_seraph.eval import rule_matches
from larc_seraph.inventory import (
    YARA_META_KEYS,
    fixture_dirs,
    load_records,
    load_sigma_rules,
    load_yara_records,
    parse_yara_meta,
)
from larc_seraph.scan import compile_yara, yara_match

ROOT = Path(__file__).resolve().parents[1]
AGENT_MARKERS = [
    "/Cursor",
    "/Claude",
    "/codex",
    "/.npm/_npx/",
    "/Code Helper",
]


@pytest.fixture(scope="module")
def yara_rules():
    return compile_yara()


@pytest.fixture(scope="module")
def sigma_by_name():
    return {rule.name: rule for rule, _path in load_sigma_rules()}


def test_pack_has_the_planned_rule_count():
    records = load_records()
    kinds = {record.kind for record in records}
    assert len(records) == 17
    assert kinds == {"yara", "sigma"}
    assert sum(record.kind == "yara" for record in records) == 11
    assert sum(record.kind == "sigma" for record in records) == 6


def test_yara_metadata_is_complete():
    for record in load_yara_records():
        _name, meta = parse_yara_meta(record.path.read_text(encoding="utf-8"))
        assert set(YARA_META_KEYS) <= set(meta)
        assert meta["author"] == "Kevin Francis Tan"
        assert meta["organization"] == "Light Architects"
        assert meta["author_url"] == "https://lightarchitects.ai"
        assert meta["date"] == "2026-11-13"
        assert meta["license"] == "Detection Rule License 1.1"
        assert meta["severity"] in {"critical", "high", "medium", "low"}
        assert meta["reference"].startswith("https://")
        assert "T" in meta["attack_technique"]


def test_sigma_metadata_is_complete():
    for rule, path in load_sigma_rules():
        assert rule.name
        assert rule.author == "Kevin Francis Tan / Light Architects"
        assert rule.date.isoformat() == "2026-11-13"
        assert rule.license == "Detection Rule License 1.1"
        assert rule.level is not None
        assert str(rule.status) == "experimental"
        assert rule.references
        assert rule.falsepositives
        assert rule.scope
        assert any(tag.namespace == "attack" and tag.name.startswith("t") for tag in rule.tags)
        assert path.suffix == ".yml"
        assert 10 <= len(path.name) <= 90


def test_agent_marker_lists_stay_in_sync():
    expected = AGENT_MARKERS
    specs = {
        "macos_agent_writes_authorized_keys.yml": ("selection_agent_image", "selection_agent_parent"),
        "macos_agent_modifies_shell_rc.yml": ("selection_agent_image", "selection_agent_parent"),
        "macos_agent_piped_shell.yml": ("selection_parent",),
    }
    for filename, keys in specs.items():
        document = yaml.safe_load((ROOT / "rules" / "sigma" / filename).read_text(encoding="utf-8"))
        for key in keys:
            block = document["detection"][key]
            field = "ParentImage|contains" if "parent" in key else "Image|contains"
            assert block[field] == expected


def test_every_rule_has_labelled_fixtures(yara_rules, sigma_by_name):
    for record in load_records():
        positive, negative = fixture_dirs(record.kind, record.name)
        positives = [path for path in positive.rglob("*") if path.is_file()]
        negatives = [path for path in negative.rglob("*") if path.is_file()]
        assert positives, record.name
        assert negatives, record.name
        for path in positives + negatives:
            text = path.read_text(encoding="utf-8")
            assert "synthetic-benign" in text, path


def test_yara_fixtures_match_only_the_documented_rule(yara_rules):
    for record in load_yara_records():
        positive, negative = fixture_dirs("yara", record.name)
        for path in positive.rglob("*"):
            if not path.is_file():
                continue
            hits = {match.rule for match in yara_match(yara_rules, path=str(path))}
            assert hits == {record.name}, (path, hits)
        for path in negative.rglob("*"):
            if not path.is_file():
                continue
            hits = {match.rule for match in yara_match(yara_rules, path=str(path))}
            assert hits == set(), (path, hits)


def test_yara_known_good_matches_nothing(yara_rules):
    folder = ROOT / "tests" / "fixtures" / "yara" / "known_good"
    for path in folder.iterdir():
        hits = {match.rule for match in yara_match(yara_rules, path=str(path))}
        assert hits == set(), (path.name, hits)


def test_sigma_fixtures_match_only_the_documented_rule(sigma_by_name):
    for name, rule in sigma_by_name.items():
        positive, negative = fixture_dirs("sigma", name)
        for path in positive.iterdir():
            event = json.loads(path.read_text(encoding="utf-8"))
            hits = sorted(
                other for other, candidate in sigma_by_name.items() if rule_matches(candidate, event)
            )
            assert hits == [name], (path, hits)
        for path in negative.iterdir():
            event = json.loads(path.read_text(encoding="utf-8"))
            hits = [
                other for other, candidate in sigma_by_name.items() if rule_matches(candidate, event)
            ]
            assert hits == [], (path, hits)


def test_sigma_known_good_matches_nothing(sigma_by_name):
    folder = ROOT / "tests" / "fixtures" / "sigma" / "known_good"
    for path in folder.iterdir():
        event = json.loads(path.read_text(encoding="utf-8"))
        hits = [name for name, rule in sigma_by_name.items() if rule_matches(rule, event)]
        assert hits == [], (path.name, hits)


def test_non_unicode_fixtures_are_ascii():
    allowed = {
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/positive/tags/AGENTS.md",
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/positive/bidi/CLAUDE.md",
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/negative/flag/AGENTS.md",
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/negative/bin/AGENTS.md",
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/positive/tool/mcp.json",
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/negative/vendor/CHANGELOG.md",
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Unsafe_Directive/positive/homo/GEMINI.md",
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Unsafe_Directive/positive/zw/CLAUDE.md",
    }
    for path in (ROOT / "tests" / "fixtures").rglob("*"):
        if not path.is_file() or path in allowed:
            continue
        path.read_text(encoding="ascii")


def test_unicode_fixtures_contain_the_documented_scalars():
    tags = (
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/positive/tags/AGENTS.md"
    ).read_text(encoding="utf-8")
    assert "\U000E0001" in tags
    assert "\U000E007F" in tags
    assert any(0xE0000 <= ord(char) <= 0xE007F for char in tags)
    bidi = (
        ROOT / "tests/fixtures/yara/SERAPH_Instruction_Hidden_Unicode/positive/bidi/CLAUDE.md"
    ).read_text(encoding="utf-8")
    assert "\u202e" in bidi


def test_sigma_check_passes():
    sigma = shutil.which("sigma")
    if sigma is None:
        candidate = Path.home() / ".local" / "bin" / "sigma"
        sigma = str(candidate) if candidate.is_file() else None
    if sigma is None:
        pytest.fail("sigma CLI is not installed. pip install -e '.[test]'")
    # d3_fendtag downloads the D3FEND ontology before it looks at the tag
    # namespace. This pack has no D3FEND tags. Excluding it keeps the rest of
    # sigma check, including ATT&CK tag validation, offline-safe.
    result = subprocess.run(
        [
            sigma,
            "check",
            "--fail-on-issues",
            "--exclude",
            "d3_fendtag",
            str(ROOT / "rules" / "sigma"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_rules_compile_as_one_yara_set():
    compiled = compile_yara()
    assert isinstance(compiled, yara.Rules)
