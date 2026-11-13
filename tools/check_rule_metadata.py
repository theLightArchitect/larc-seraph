"""Fail when a YARA or Sigma rule is missing the metadata CI requires.

YARA: author, date, modified, description, reference, id, version, and ATT&CK
tags (attack_technique, attack_tactic). Sigma: id, status, level, tags,
logsource, and falsepositives. This checks presence and shape. It does not
score rules and it does not change them.
"""

from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from larc_seraph.inventory import PATH_YARA_DIR, SIGMA_DIR, YARA_DIR, parse_yara_meta  # noqa: E402
from larc_seraph.inventory import load_sigma_rules  # noqa: E402

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?(?:, T\d{4}(?:\.\d{3})?)*$")
_RULE = re.compile(r"^rule\s+[A-Za-z0-9_]+\s*\{", re.M)
_YARA_REQUIRED = (
    "author",
    "date",
    "modified",
    "description",
    "reference",
    "id",
    "version",
    "attack_technique",
    "attack_tactic",
)
_SIGMA_STATUS = {"experimental", "test", "stable", "deprecated", "unsupported"}
_SIGMA_LEVEL = {"informational", "low", "medium", "high", "critical"}


def _nonempty(meta: dict[str, str], key: str) -> str | None:
    value = meta.get(key, "")
    if not value.strip():
        return f"missing {key}"
    return None


def _check_yara_file(path: Path, seen: dict[str, str], *, forge: bool) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    if forge and "filepath" in text:
        problems.append(f"{path.name}: Forge rule mentions filepath")
    if not forge and "filepath" not in text:
        problems.append(f"{path.name}: path-scoped rule does not read filepath")
    rules = _RULE.findall(text)
    if len(rules) != 1:
        problems.append(f"{path.name}: expected one rule, found {len(rules)}")
        return problems
    try:
        name, meta = parse_yara_meta(text)
    except ValueError as exc:
        problems.append(f"{path.name}: {exc}")
        return problems
    for key in _YARA_REQUIRED:
        missing = _nonempty(meta, key)
        if missing:
            problems.append(f"{name}: {missing}")
    if meta.get("date") and not _DATE.match(meta["date"]):
        problems.append(f"{name}: date is not YYYY-MM-DD")
    if meta.get("modified") and not _DATE.match(meta["modified"]):
        problems.append(f"{name}: modified is not YYYY-MM-DD")
    if meta.get("reference") and not meta["reference"].startswith("https://"):
        problems.append(f"{name}: reference is not an https URL")
    technique = meta.get("attack_technique", "")
    if technique and not _TECHNIQUE.match(technique):
        problems.append(f"{name}: attack_technique is not ATT&CK technique ids")
    rule_id = meta.get("id", "")
    if rule_id:
        if forge and rule_id.endswith("-PATH"):
            problems.append(f"{name}: Forge id must stay the canonical SERAPH-YARA id")
        if not forge and not rule_id.endswith("-PATH"):
            problems.append(f"{name}: path-scoped id must end in -PATH")
        if not forge and not name.endswith("_Path"):
            problems.append(f"{name}: path-scoped rule name must end in _Path")
        if rule_id in seen:
            problems.append(f"{name}: duplicate id {rule_id} (also {seen[rule_id]})")
        seen[rule_id] = name
    return problems


def check_yara() -> list[str]:
    problems: list[str] = []
    seen: dict[str, str] = {}
    paths = sorted(YARA_DIR.glob("*.yar"))
    if not paths:
        return ["rules/yara has no .yar files"]
    for path in paths:
        problems.extend(_check_yara_file(path, seen, forge=True))
    twins = sorted(PATH_YARA_DIR.glob("*.yar"))
    if len(twins) != 9:
        problems.append(f"rules/path-scoped has {len(twins)} rules, expected 9")
    for path in twins:
        problems.extend(_check_yara_file(path, seen, forge=False))
    return problems


def _logsource_value(logsource: object, field: str) -> str:
    if logsource is None:
        return ""
    if isinstance(logsource, dict):
        return str(logsource.get(field) or "")
    return str(getattr(logsource, field, "") or "")


def check_sigma() -> list[str]:
    problems: list[str] = []
    seen: dict[str, str] = {}
    if not list(SIGMA_DIR.glob("*.yml")):
        return ["rules/sigma has no .yml files"]
    try:
        loaded = load_sigma_rules()
    except ValueError as exc:
        return [str(exc)]
    for rule, path in loaded:
        label = path.name
        try:
            uuid.UUID(str(rule.id))
        except (ValueError, TypeError, AttributeError):
            problems.append(f"{label}: id is not a UUID")
        else:
            rule_id = str(rule.id)
            if rule_id in seen:
                problems.append(f"{label}: duplicate id {rule_id} (also {seen[rule_id]})")
            seen[rule_id] = label
        status = str(rule.status or "")
        if status not in _SIGMA_STATUS:
            problems.append(f"{label}: missing or unknown status ({status or 'empty'})")
        level = str(rule.level or "")
        if level not in _SIGMA_LEVEL:
            problems.append(f"{label}: missing or unknown level ({level or 'empty'})")
        tags = list(rule.tags or [])
        if not tags:
            problems.append(f"{label}: missing tags")
        elif not any(getattr(tag, "namespace", "") == "attack" for tag in tags):
            problems.append(f"{label}: tags do not include an attack.* tag")
        product = _logsource_value(rule.logsource, "product")
        category = _logsource_value(rule.logsource, "category")
        if not product or not category:
            problems.append(f"{label}: logsource needs product and category")
        positives = [item for item in (rule.falsepositives or []) if str(item).strip()]
        if not positives:
            problems.append(f"{label}: missing falsepositives")
    return problems


def main() -> int:
    problems = check_yara() + check_sigma()
    if problems:
        print("rule metadata check failed:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("rule metadata check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
