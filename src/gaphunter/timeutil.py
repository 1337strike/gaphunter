"""UTC timestamp helpers shared by the collector and the CLI."""

from __future__ import annotations

import re
from datetime import UTC, datetime

_FRACTION = re.compile(r"\.(\d+)")


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime.

    Accepts Windows-style values with 7 fractional digits and a trailing ``Z``; naive
    values are taken to be UTC (event-log ``SystemTime`` and Sysmon ``UtcTime`` are UTC).
    """
    text = value.strip().replace(" ", "T", 1)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # datetime only carries microseconds: trim .1234567 to .123456
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"not an ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def to_systemtime(value: datetime) -> str:
    """Format for event-log XPath filters: ``2026-11-14T02:16:00.000Z``."""
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"
