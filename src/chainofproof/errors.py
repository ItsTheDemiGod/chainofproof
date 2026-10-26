"""Base class for expected, user-facing errors (the CLI prints these as one clean line)."""


class UserError(Exception):
    """An expected failure (unknown ID, missing file, integrity problem...)."""
