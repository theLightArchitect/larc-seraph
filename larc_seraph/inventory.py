"""Load SERAPH rules and the metadata the docs and tests share."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parents[1]
YARA_DIR = ROOT / "rules" / "yara"
SIGMA_DIR = ROOT / "rules" / "sigma"
FIXTURE_DIR = ROOT / "tests" / "fixtures"
CONTENT_DIR = ROOT / "docs" / "content"

YARA_META_KEYS = (
    "id",
    "title",
    "author",
    "organization",
    "author_url",
    "date",
    "modified",
    "version",
    "severity",
    "description",
    "attack_technique",
    "attack_tactic",
    "reference",
    "scope",
    "false_positives",
    "license",
)

_META_LINE = re.compile(r'^\s+([A-Za-z0-9_]+)\s*=\s*"((?:\\.|[^"\\])*)"\s*$')
_RULE_NAME = re.compile(r"^rule\s+([A-Za-z0-9_]+)\s*\{", re.M)


@dataclass(frozen=True)
class RuleRecord:
    kind: str
    name: str
    seraph_id: str
    title: str
    severity: str
    description: str
    author: str
    date: str
    attack: str
    tactic: str
    references: tuple[str, ...]
    false_positives: tuple[str, ...]
    scope: str
    license: str
    path: Path
    level: str


def parse_yara_meta(text: str) -> tuple[str, dict[str, str]]:
    name_match = _RULE_NAME.search(text)
    if not name_match:
        raise ValueError("YARA rule name not found")
    name = name_match.group(1)
    meta_start = text.find("meta:")
    strings_at = text.find("strings:", meta_start)
    if meta_start < 0 or strings_at < 0:
        raise ValueError(f"{name}: meta block not found")
    meta: dict[str, str] = {}
    for line in text[meta_start:strings_at].splitlines():
        matched = _META_LINE.match(line)
        if matched:
            meta[matched.group(1)] = bytes(matched.group(2), "utf-8").decode("unicode_escape")
    return name, meta


def load_yara_records() -> list[RuleRecord]:
    records: list[RuleRecord] = []
    for path in sorted(YARA_DIR.glob("*.yar")):
        name, meta = parse_yara_meta(path.read_text(encoding="utf-8"))
        missing = [key for key in YARA_META_KEYS if key not in meta]
        if missing:
            raise ValueError(f"{path.name} missing meta: {', '.join(missing)}")
        records.append(
            RuleRecord(
                kind="yara",
                name=name,
                seraph_id=meta["id"],
                title=meta["title"],
                severity=meta["severity"],
                description=meta["description"],
                author=meta["author"],
                date=meta["date"],
                attack=meta["attack_technique"],
                tactic=meta["attack_tactic"],
                references=tuple(
                    meta[key] for key in sorted(meta) if key == "reference" or key.startswith("reference_")
                ),
                false_positives=(meta["false_positives"],),
                scope=meta["scope"],
                license=meta["license"],
                path=path,
                level=meta["severity"],
            )
        )
    return records


def load_sigma_rules() -> list[tuple[SigmaRule, Path]]:
    loaded: list[tuple[SigmaRule, Path]] = []
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        if rule.errors:
            raise ValueError(f"{path.name}: {rule.errors[0]}")
        loaded.append((rule, path))
    return loaded


SIGMA_IDS = {
    "SERAPH_MacOS_Agent_Writes_Authorized_Keys": "SERAPH-SIGMA-011",
    "SERAPH_MacOS_Agent_Modifies_Shell_RC": "SERAPH-SIGMA-012",
    "SERAPH_MacOS_Interpreter_Drops_Launch_Plist": "SERAPH-SIGMA-013",
    "SERAPH_MacOS_SSH_Reverse_Lax_HostKey": "SERAPH-SIGMA-014",
    "SERAPH_MacOS_Agent_Piped_Shell": "SERAPH-SIGMA-015",
    "SERAPH_MacOS_Terminal_Piped_Shell": "SERAPH-SIGMA-016",
}


def load_sigma_records() -> list[RuleRecord]:
    records: list[RuleRecord] = []
    for rule, path in load_sigma_rules():
        if not rule.name:
            raise ValueError(f"{path.name} has no name")
        if rule.name not in SIGMA_IDS:
            raise ValueError(f"{rule.name} has no SERAPH sigma id")
        techniques = [tag.name for tag in rule.tags if tag.name.startswith("t")]
        tactics = [tag.name for tag in rule.tags if not tag.name.startswith("t")]
        records.append(
            RuleRecord(
                kind="sigma",
                name=rule.name,
                seraph_id=SIGMA_IDS[rule.name],
                title=rule.title,
                severity=str(rule.level) if rule.level else "",
                description=" ".join((rule.description or "").split()),
                author=rule.author or "",
                date=rule.date.isoformat() if rule.date else "",
                attack=", ".join(techniques),
                tactic=", ".join(tactics),
                references=tuple(rule.references),
                false_positives=tuple(rule.falsepositives),
                scope="; ".join(rule.scope or []),
                license=rule.license or "",
                path=path,
                level=str(rule.level) if rule.level else "",
            )
        )
    return records


def load_records() -> list[RuleRecord]:
    records = load_yara_records() + load_sigma_records()
    return sorted(records, key=lambda record: (record.kind != "yara", record.seraph_id, record.name))


def fixture_dirs(kind: str, name: str) -> tuple[Path, Path]:
    base = FIXTURE_DIR / kind / name
    return base / "positive", base / "negative"


def writeup_path(record: RuleRecord) -> Path:
    return CONTENT_DIR / "rules" / f"{record.name}.md"
