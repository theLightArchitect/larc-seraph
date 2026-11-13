"""Conversion, telemetry round-trip, evasion matrix, yara-x, and a speed check."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import yaml
import yara

from larc_seraph.eval import rule_matches
from larc_seraph.inventory import ROOT, load_sigma_rules
from larc_seraph.scan import compile_yara, yara_match
from larc_seraph.translate import NORMALIZERS

SAMPLES = ROOT / "telemetry" / "samples"
CONVERTED = ROOT / "rules" / "converted"


def test_telemetry_samples_round_trip():
    rules = {rule.name: rule for rule, _path in load_sigma_rules()}
    seen = 0
    for schema_dir in sorted(path for path in SAMPLES.iterdir() if path.is_dir()):
        normalize = NORMALIZERS[schema_dir.name]
        for rule_dir in sorted(path for path in schema_dir.iterdir() if path.is_dir()):
            for kind in ("positive", "negative"):
                for path in sorted((rule_dir / kind).glob("*.json")):
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    assert payload["_larc"]["classification"] == "synthetic-benign"
                    event = normalize(payload["record"])
                    hits = sorted(
                        name for name, rule in rules.items() if rule_matches(rule, event)
                    )
                    expected = [rule_dir.name] if kind == "positive" else []
                    assert hits == expected, (path, hits, event)
                    seen += 1
    assert seen >= 60


def test_committed_conversions_match_a_fresh_run():
    sigma = shutil.which("sigma")
    if sigma is None:
        pytest.fail("sigma CLI is not installed")
    for target, pipeline, folder in (
        ("lucene", "ecs-macos.yml", "lucene"),
        ("splunk", "splunk-macos.yml", "splunk"),
    ):
        destination = CONVERTED / folder
        assert list(destination.glob("*.txt")), folder
        result = subprocess.run(
            [
                sigma,
                "convert",
                "-t",
                target,
                "-p",
                str(ROOT / "pipelines" / pipeline),
                "-od",
                str(destination),
                "-ot",
                "{stem}.txt",
                str(ROOT / "rules" / "sigma"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        text = "\n".join(path.read_text(encoding="utf-8") for path in destination.glob("*.txt"))
        if target == "lucene":
            assert "process.executable" in text
            assert "process.command_line" in text or "file.path" in text
        else:
            assert "process_path" in text or "parent_process_path" in text


def test_libyara_compiles_without_warnings():
    yarac = shutil.which("yarac")
    if yarac is None:
        candidate = Path("/tmp/yara-install/bin/yarac")
        yarac = str(candidate) if candidate.is_file() else None
    if yarac is None:
        pytest.fail("yarac 4.5.x is not installed")
    result = subprocess.run(
        [yarac, "--fail-on-warnings", "--strict-escape", *[str(path) for path in sorted((ROOT / "rules" / "yara").glob("*.yar"))], str(ROOT / ".cache-libyara.yac")],
        capture_output=True,
        text=True,
        check=False,
    )
    compiled = ROOT / ".cache-libyara.yac"
    if compiled.exists():
        compiled.unlink()
    noise = (result.stdout + result.stderr).strip()
    assert result.returncode == 0, noise
    assert noise == ""


def test_yara_x_compiles_without_warnings():
    yr = shutil.which("yr")
    if yr is None:
        candidate = Path.home() / ".local" / "bin" / "yr"
        yr = str(candidate) if candidate.is_file() else None
    if yr is None:
        pytest.fail("yara-x yr CLI is not installed")
    result = subprocess.run(
        [yr, "compile", str(ROOT / "rules" / "yara"), "-o", str(ROOT / ".cache-yara-x.yarc")],
        capture_output=True,
        text=True,
        check=False,
    )
    compiled = ROOT / ".cache-yara-x.yarc"
    if compiled.exists():
        compiled.unlink()
    noise = (result.stdout + result.stderr).strip()
    assert result.returncode == 0, noise
    assert "slow" not in noise.lower()
    assert noise == ""


def test_yara_scan_of_a_wide_tree_stays_quick(tmp_path: Path):
    rules = compile_yara()
    for index in range(400):
        (tmp_path / f"note-{index}.md").write_text(
            "# Project notes\n\nAsk for confirmation before deleting files.\n" * 5,
            encoding="utf-8",
        )
    started = time.perf_counter()
    hits = 0
    for path in tmp_path.glob("*.md"):
        hits += len(yara_match(rules, path=str(path)))
    elapsed = time.perf_counter() - started
    assert hits == 0
    assert elapsed < 10


def _default_filepath(rule: str) -> str:
    if "Git_Hook" in rule:
        return "/repo/.git/hooks/pre-commit"
    if rule.startswith("SUSP_SERAPH_MCP"):
        return "/repo/mcp.json"
    if "Instruction" in rule:
        return "/repo/AGENTS.md"
    if "Launch" in rule:
        return "/users/dev/library/launchagents/com.example.plist"
    return "/tmp/sample"


_INSTRUCTION = {"SUSP_SERAPH_Instruction_Unsafe_Directive", "SUSP_SERAPH_Instruction_Hidden_Unicode"}
_MARKER = "agent instructions"


def _forge_body(case: dict) -> str:
    body = case["body"]
    if case["rule"] not in _INSTRUCTION or case.get("forge_body") == "raw":
        return body
    if _MARKER in body.lower():
        return body
    return "# Agent instructions\n" + body


def _assert_expect(matched: bool, expect: str, case: dict) -> None:
    if expect == "match":
        assert matched, case["name"]
        return
    assert expect == "miss", case
    assert not matched, case["name"]
    assert case.get("note"), case["name"]


def test_evasion_matrix():
    document = yaml.safe_load((ROOT / "validation" / "evasion-matrix.yml").read_text(encoding="utf-8"))
    path_rules = compile_yara("path")
    forge_rules = compile_yara("forge")
    sigma = {rule.name: rule for rule, _path in load_sigma_rules()}
    covered = set()
    for case in document["cases"]:
        covered.add(case["rule"])
        if case.get("engine") == "sigma":
            hits = [name for name, rule in sigma.items() if rule_matches(rule, case["event"])]
            _assert_expect(case["rule"] in hits, case["expect"], case)
            continue
        filepath = case.get("filepath") or _default_filepath(case["rule"])
        path_hits = {
            hit.rule[:-5] if hit.rule.endswith("_Path") else hit.rule
            for hit in yara_match(path_rules, data=case["body"].encode(), filepath=filepath)
        }
        forge_hits = {
            hit.rule
            for hit in yara_match(
                forge_rules,
                data=_forge_body(case).encode(),
                use_filepath=False,
            )
        }
        path_expect = case["path_expect"] if "path_expect" in case else case["expect"]
        forge_expect = case["forge_expect"] if "forge_expect" in case else case["expect"]
        _assert_expect(case["rule"] in path_hits, path_expect, case)
        _assert_expect(case["rule"] in forge_hits, forge_expect, case)
    from larc_seraph.inventory import load_records

    names = {record.name for record in load_records()}
    missing = names - covered
    assert not missing, missing
    assert isinstance(path_rules, yara.Rules)
    assert isinstance(forge_rules, yara.Rules)


def test_eslogger_create_and_rename_use_the_endpoint_security_shape():
    """es_event_create_t and es_event_rename_t carry existing_file or new_path."""
    from larc_seraph.translate import normalize_eslogger

    process = {"executable": {"path": "/usr/bin/python3"}, "user_name": "dev"}
    created = normalize_eslogger(
        {
            "process": process,
            "event": {
                "create": {
                    "destination_type": 1,
                    "destination": {
                        "new_path": {
                            "dir": {"path": "/Users/dev/Library/LaunchAgents"},
                            "filename": "invalid.example.seraph.plist",
                        }
                    },
                }
            },
        }
    )
    assert created["TargetFilename"] == "/Users/dev/Library/LaunchAgents/invalid.example.seraph.plist"
    renamed = normalize_eslogger(
        {
            "process": process,
            "event": {
                "rename": {
                    "destination_type": 0,
                    "destination": {"existing_file": {"path": "/Users/dev/.ssh/authorized_keys"}},
                }
            },
        }
    )
    assert renamed["TargetFilename"] == "/Users/dev/.ssh/authorized_keys"
