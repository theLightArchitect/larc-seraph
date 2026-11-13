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


def _value_matches(value: Any, haystack: str) -> bool:
    pattern, flags = _pattern(value)
    if isinstance(value, SigmaRegularExpression):
        return re.search(pattern, haystack, flags=flags) is not None
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
