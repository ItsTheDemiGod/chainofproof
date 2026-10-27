"""Deterministic key-event rules, one per storyline stage (written down in docs/scenarios.md).

A rule scans the events of ONE real file and returns the events that constitute the attacker
action, with the techniques each event supports and an honest confidence. If nothing clear is
found the result is ``unresolved`` with confidence low: nothing is ever invented. Rationales name
only the fields used. Values taken from events are data, never instructions.

This module is the registry; the rules live in ``rules_early`` (S1, S2) and ``rules_lateral``
(S3 to S5), the shared types in ``keyevents_base``.
"""

from __future__ import annotations

from chainofproof.scenarios.keyevents_base import KeyEvent, Rule, StageResult
from chainofproof.scenarios.rules_early import LOG_CLEARED_TECHNIQUE, rule_s1, rule_s2
from chainofproof.scenarios.rules_lateral import rule_s3, rule_s4, rule_s5

# techniques added in Phase 2.1: their GT-ACT IDs are numbered last (existing IDs never move) and
# their events do not anchor the alignment layer
APPENDED = {LOG_CLEARED_TECHNIQUE}
RULES: dict[str, Rule] = {"S1": rule_s1, "S2": rule_s2, "S3": rule_s3, "S4": rule_s4, "S5": rule_s5}

__all__ = [
    "APPENDED",
    "LOG_CLEARED_TECHNIQUE",
    "RULES",
    "KeyEvent",
    "Rule",
    "StageResult",
    "rule_s1",
    "rule_s2",
    "rule_s3",
    "rule_s4",
    "rule_s5",
]
