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
from larc_seraph.scan import compile_yara
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
        hits += len(rules.match(str(path)))
    elapsed = time.perf_counter() - started
    assert hits == 0
    assert elapsed < 10


def test_evasion_matrix():
    document = yaml.safe_load((ROOT / "validation" / "evasion-matrix.yml").read_text(encoding="utf-8"))
    rules = compile_yara()
    sigma = {rule.name: rule for rule, _path in load_sigma_rules()}
    covered = set()
    for case in document["cases"]:
        covered.add(case["rule"])
        expect = case["expect"]
        if case.get("engine") == "sigma":
            hits = [name for name, rule in sigma.items() if rule_matches(rule, case["event"])]
            matched = case["rule"] in hits
        else:
            matched = any(hit.rule == case["rule"] for hit in rules.match(data=case["body"].encode()))
        if expect == "match":
            assert matched, case["name"]
        else:
            assert expect == "miss", case
            assert not matched, case["name"]
            assert case.get("note"), case["name"]
    from larc_seraph.inventory import load_records

    names = {record.name for record in load_records()}
    missing = names - covered
    assert not missing, missing
    assert isinstance(rules, yara.Rules)
