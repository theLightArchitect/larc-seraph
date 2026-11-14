"""Evaluate Sigma rules against a normalized event dict.

This covers the Sigma subset SERAPH rules use: field equality, contains,
startswith, endswith, re, AND, OR, NOT, and ``1 of`` / ``all of`` selectors.
Sigma's default case-insensitive match is honored. It is a fixture oracle,
not a SIEM.

A list of conditions is OR, matching the Sigma specification.
"""

from __future__ import annotations

import re
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaCasedString, SigmaRegularExpression, SigmaString


def _pattern(value: Any) -> tuple[str, int]:
    flags = re.IGNORECASE
    if isinstance(value, SigmaCasedString):
        flags = 0
    if isinstance(value, SigmaString):
        return str(value.to_regex().regexp), flags
    if isinstance(value, SigmaRegularExpression):
        return str(value.regexp), flags
    return re.escape(str(value)), flags


def _has_top_level_alternation(pattern: str) -> bool:
    depth = 0
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
        index += 1
    return False


def search_form(pattern: str) -> str:
    """Drop a leading and a trailing `.*` from a regex that is run with `re.search`.

    WHY: a search already finds the pattern anywhere, so `.*x.*` and `x` give the
    same answer, but the leading `.*` makes a miss cost quadratic time in the
    length of the field, and the field is attacker-controlled. A pattern with a
    top-level `|` is left alone, because the strip is only exact for one branch.
    """
    if _has_top_level_alternation(pattern):
        return pattern
    stripped = pattern
    if stripped.startswith(".*"):
        stripped = stripped[2:]
    if stripped.endswith(".*") and not stripped.endswith("\\.*"):
        stripped = stripped[:-2]
    return stripped or pattern


def _value_matches(value: Any, haystack: str) -> bool:
    pattern, flags = _pattern(value)
    if isinstance(value, SigmaRegularExpression):
        return re.search(search_form(pattern), haystack, flags=flags) is not None
    return re.fullmatch(pattern, haystack, flags=flags) is not None


def _field_text(event: dict[str, Any], field: str) -> str | None:
    if field not in event:
        return None
    raw = event[field]
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        return " ".join(str(item) for item in raw)
    return str(raw)


def eval_condition(condition: Any, event: dict[str, Any]) -> bool:
    if isinstance(condition, ConditionAND):
        return all(eval_condition(arg, event) for arg in condition.args)
    if isinstance(condition, ConditionOR):
        return any(eval_condition(arg, event) for arg in condition.args)
    if isinstance(condition, ConditionNOT):
        return not eval_condition(condition.args[0], event)
    if isinstance(condition, ConditionFieldEqualsValueExpression):
        text = _field_text(event, condition.field)
        if text is None:
            return False
        return _value_matches(condition.value, text)
    if isinstance(condition, ConditionValueExpression):
        blob = " ".join(
            str(value)
            for key, value in event.items()
            if not str(key).startswith("_") and value is not None
        )
        return _value_matches(condition.value, blob)
    if isinstance(condition, ConditionItem):
        raise TypeError(f"Unsupported Sigma condition node: {type(condition).__name__}")
    raise TypeError(f"Unsupported Sigma condition node: {type(condition).__name__}")


def rule_matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """Return True when any parsed condition of ``rule`` matches ``event``."""

    parsed = rule.detection.parsed_condition
    if not parsed:
        return False
    return any(eval_condition(item.parsed, event) for item in parsed)
