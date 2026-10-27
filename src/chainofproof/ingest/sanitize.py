"""Sanitizer for every string that comes out of evidence (evidence is DATA, never instructions).

``sanitize`` makes text inert for display and storage: ANSI escapes, NUL and other control or
invisible-format characters are removed, whitespace controls become one space, and the length is
capped. It does NOT try to detect or interpret instruction-like text (that is Phase 7); text that
imitates instructions to an AI passes through unchanged, as plain data.
"""

from __future__ import annotations

import re
import unicodedata

DEFAULT_MAX = 2048
COMMAND_MAX = 4096
FIELD_MAX = 512

_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI sequences (colors, cursor)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences (titles, hyperlinks)
    r"|\x1b[@-Z\\-_]"  # two-character escapes
)
_SPACE_CONTROLS = {ord(c): " " for c in "\t\n\r\x0b\x0c\x85  "}


def sanitize(text: str, max_len: int = DEFAULT_MAX) -> tuple[str, bool, int]:
    """Return ``(clean_text, truncated, original_length)``.

    Order: strip ANSI escapes, turn tab/newline-like characters into a space, drop NUL and all
    other control (Cc) and invisible-format (Cf, e.g. bidi overrides, zero-width) characters, then
    cap the length. ``original_length`` is the length of the input before any change.
    """
    original = len(text)
    s = _ANSI.sub("", text).translate(_SPACE_CONTROLS)
    s = "".join(c for c in s if unicodedata.category(c) not in ("Cc", "Cf"))
    truncated = len(s) > max_len
    return (s[:max_len] if truncated else s), truncated, original


def clean(text: str, max_len: int = DEFAULT_MAX) -> str:
    """Sanitized text only (when the truncation flag is not needed)."""
    return sanitize(text, max_len)[0]
