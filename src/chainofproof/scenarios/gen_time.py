"""Per-host log spans and a mildly non-uniform time density for the benign background (v4).

Spans (virtual UTC, same day as the scenario start): WS-FIN-07 07:30-15:30, SRV-FILE-02
06:00-16:00, DC-01 08:00-11:30. The key lines therefore sit at different relative positions on
each host. Times are whole seconds drawn uniformly inside 15-minute buckets, so seconds are not
systematically :00.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from chainofproof.scenarios.gen_context import GenContext

SPANS = {
    "WS-FIN-07": ((7, 30), (15, 30)),
    "SRV-FILE-02": ((6, 0), (16, 0)),
    "DC-01": ((8, 0), (11, 30)),
}
BUCKET_SECONDS = 900


def host_span(ctx: GenContext, host: str) -> tuple[datetime, datetime]:
    """(first, last) virtual time of a host's log."""
    day = ctx.start.replace(hour=0, minute=0, second=0, microsecond=0)
    (h0, m0), (h1, m1) = SPANS[host]
    return day + timedelta(hours=h0, minutes=m0), day + timedelta(hours=h1, minutes=m1)


def _weight(hour: float) -> float:
    """Relative activity: quiet early/late, busy mid-morning and early afternoon, lunch dip."""
    if hour < 8:
        return 0.4
    if hour < 9:
        return 1.0
    if hour < 12:
        return 1.8
    if hour < 13:
        return 1.0
    return 1.5 if hour < 15 else 0.7


def sample_time(rng: random.Random, lo: datetime, hi: datetime) -> datetime:
    """A whole-second time in [lo, hi) with the working-hours density above."""
    total = int((hi - lo).total_seconds())
    starts = list(range(0, total, BUCKET_SECONDS))
    weights = [
        _weight((lo + timedelta(seconds=s + BUCKET_SECONDS // 2)).hour + 0.5) for s in starts
    ]
    start = rng.choices(starts, weights)[0]
    return lo + timedelta(seconds=rng.randrange(start, min(start + BUCKET_SECONDS, total)))
