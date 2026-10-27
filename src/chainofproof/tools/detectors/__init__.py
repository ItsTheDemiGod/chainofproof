"""The five contradiction/anomaly detectors: separate tools, never run automatically (rule D2)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from chainofproof.config import (
    ClockSkewParams,
    LogClearParams,
    LogGapParams,
    TimestompParams,
    UnmatchedConnectionParams,
)
from chainofproof.tools.detectors.base import Hit
from chainofproof.tools.detectors.clock_skew import detect_clock_skew
from chainofproof.tools.detectors.log_clear import detect_log_clear
from chainofproof.tools.detectors.log_gap import detect_log_gap
from chainofproof.tools.detectors.timestomp import detect_timestomp
from chainofproof.tools.detectors.unmatched_conn import detect_unmatched_connection

DetectorFn = Callable[[Any, Any], list[Hit]]
DETECTORS: dict[str, tuple[DetectorFn, type[BaseModel]]] = {
    "timestomp": (detect_timestomp, TimestompParams),
    "clock_skew": (detect_clock_skew, ClockSkewParams),
    "log_gap": (detect_log_gap, LogGapParams),
    "log_clear": (detect_log_clear, LogClearParams),
    "unmatched_connection": (detect_unmatched_connection, UnmatchedConnectionParams),
}

__all__ = ["DETECTORS", "Hit"]
