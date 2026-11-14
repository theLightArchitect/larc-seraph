"""Conversion, telemetry round-trip, evasion matrix, yara-x, and a speed check."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import yaml
import yara

from larc_seraph.eval import rule_matches, search_form
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


def test_extra_agent_markers_stay_in_sync():
    """The hardening round added hosts beside the shared list the older test pins."""
    sigma_dir = ROOT / "rules" / "sigma"

    def load(name: str) -> dict:
        return yaml.safe_load((sigma_dir / name).read_text(encoding="utf-8"))["detection"]

    expected = [
        {"Image|contains": "/Windsurf"},
        {"Image|endswith": ["/opencode", "/aider", "/goose"]},
    ]
    parent_expected = [
        {"ParentImage|contains": "/Windsurf"},
        {"ParentImage|endswith": ["/opencode", "/aider", "/goose"]},
    ]
    for name in ("macos_agent_writes_authorized_keys.yml", "macos_agent_modifies_shell_rc.yml"):
        detection = load(name)
        assert detection["selection_agent_extra_image"] == expected, name
        assert detection["selection_agent_extra_parent"] == parent_expected, name
    assert load("macos_agent_piped_shell.yml")["selection_parent_extra"] == parent_expected


def test_no_catastrophic_backtracking_in_a_hand_written_regex():
    """A crafted command line or sentence must not make a backtracking engine slow.

    Both inputs took exponential time with an earlier pattern: about five times
    longer per extra assignment in the Sigma temp-run regex, about twice as long
    per repeat of "e.g.e" with the sentence unit that also matched abbreviations.
    The bounds are generous. They fail by orders of magnitude, not by noise.
    """
    import re
    import time

    from larc_seraph.phrases import instruction_bypass

    sigma_rules = {rule.name: rule for rule, _path in load_sigma_rules()}
    document = yaml.safe_load((ROOT / "rules" / "sigma" / "macos_agent_piped_shell.yml").read_text(encoding="utf-8"))
    regexes = [
        value
        for selection in document["detection"].values()
        if isinstance(selection, dict)
        for key, value in selection.items()
        if key.endswith("|re") and isinstance(value, str)
    ]
    assert regexes, "expected at least one regex in the rule"
    assert "SERAPH_MacOS_Agent_Piped_Shell" in sigma_rules
    for pattern in regexes:
        compiled = re.compile(search_form(pattern), re.IGNORECASE)
        for count in (40, 200, 20000):
            line = "x; env " + " ".join(["a=b=c=d=e=f"] * count) + " nope"
            started = time.perf_counter()
            compiled.search(line)
            assert time.perf_counter() - started < 1.0, (pattern, count)
        # Every separator starts a new attempt, so an attempt must stop at the next one.
        for line in ("x;" + "env a=;" * 20000 + " nope", "x" + "; env a=b" * 20000 + " nope", "x" + "&& sudo env A=1 " * 20000 + "nope"):
            started = time.perf_counter()
            compiled.search(line)
            assert time.perf_counter() - started < 1.0, (pattern, line[:20])
        for line in (
            "x;" + "env a='" * 20000,
            "x" + "; env a='b' " * 20000 + "nope",
            'x; env a="' * 20000,
            "x; env " + "a=\\ " * 20000 + "nope",
            "x; env " + "a=\\" * 20000,
            "x; env " + "'a=b' " * 20000 + "nope",
            "x; env " + "\\'a " * 20000,
        ):
            started = time.perf_counter()
            compiled.search(line)
            assert time.perf_counter() - started < 1.0, (pattern, line[:20])
        if "tmp/" not in pattern:
            continue  # the two checks below are about the temp-path regex only
        # A quoted value with a blank in it is still an assignment.
        assert compiled.search("x; env X='a b' bash /tmp/n"), pattern
        # Quotes and escapes in an assignment are what a shell strips before it runs env.
        for hit in ("x; env 'X=1' bash /tmp/n", "x; env X=a\\'b bash /tmp/n", 'x; env "A B"=1 bash /tmp/n', "x; env X=a\\;b bash /tmp/n"):
            assert compiled.search(hit), (pattern, hit)
        assert not compiled.search("x; env X=a\\ bash /tmp/n"), pattern  # the escaped blank makes /tmp/n the command
        # Padding must not hide the shell.
        padded = "x; env " + " ".join(["a=b"] * 200) + " bash /tmp/n"
        assert compiled.search(padded), pattern

    header = b"Agent instructions.\n\n"
    for body in (b"e.g.e" * 40, b"i.e.i" * 40, b".x" * 80, b"e.g." * 40, b"e.g. " * 40, b"e.g.\t" * 40, b"i.e. e.g.e " * 20):
        started = time.perf_counter()
        instruction_bypass(header + b"Approval is not required " + body + b"\n", "/x/AGENTS.md", use_filepath=True)
        assert time.perf_counter() - started < 1.0, body[:12]


def test_the_repeated_sentence_unit_stays_small():
    """A repeated group with more branches made libyara stop on a 4 MB executable.

    With e.g. and i.e. as branches of SENTENCE_UNIT (four branches, repeated up to
    160 times, behind a 1000 byte line prefix) libyara reported "too many fibers" on
    two large binaries and the scan of those files did not finish. The unit has two
    branches. Abbreviations have their own patterns without a repeated alternation.
    """
    from larc_seraph.phrases import ABBREVIATION, SENTENCE_UNIT

    assert SENTENCE_UNIT.count("|") == 1, SENTENCE_UNIT
    assert "e\\.g" not in SENTENCE_UNIT and "i\\.e" not in SENTENCE_UNIT
    assert ABBREVIATION


def test_search_form_gives_the_same_answer_as_the_written_regex() -> None:
    cases = [
        (r".*(curl|wget|fetch|base64)\t.*", ["curl\t-s", "x curl\ty", "curl -s", "base64\t", "", "\ncurl\t"]),
        (r"a.*", ["a", "ba", "b", ""]),
        (r".*a|b", ["a", "b", "c"]),
        (r"\.*x", ["x", "..x", "y"]),
    ]
    for pattern, texts in cases:
        for text in texts:
            written = re.search(pattern, text, re.IGNORECASE) is not None
            assert (re.search(search_form(pattern), text, re.IGNORECASE) is not None) == written, (pattern, text)
    assert search_form(r".*(curl|wget)\t.*") == r"(curl|wget)\t"

