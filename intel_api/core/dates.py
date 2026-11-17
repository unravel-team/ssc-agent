"""Dates: one UTC format for when an item was published, plus the event dates its text mentions.

A post published today about "the March 30 attack" is old news; mentioned_dates lets alerts say so.
"""

import re
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime

_MONTHS = {
    m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)
}
_M = r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?"
_PATTERNS = [
    (re.compile(rf"\b{_M}\s+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+(20\d\d)\b", re.I), ("m", "d", "y")),  # March 30, 2026
    (re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+{_M},?\s+(20\d\d)\b", re.I), ("d", "m", "y")),  # 30 March 2026
    (re.compile(r"\b(20\d\d)-(\d\d)-(\d\d)\b"), ("y", "m", "d")),  # 2026-03-30
]


def normalize(ts):
    """Any ISO / RFC-2822-ish timestamp -> 'YYYY-MM-DDTHH:MM:SS+00:00' (UTC); date-only stays 'YYYY-MM-DD'."""
    if not ts:
        return None
    if isinstance(ts, datetime):
        d = ts
    else:
        s = str(ts).strip()
        if re.fullmatch(r"\d{4}-\d\d-\d\d", s):
            return s
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            try:
                d = parsedate_to_datetime(s)
            except (TypeError, ValueError, IndexError, OverflowError):  # not a date we can read: keep the text
                return s[:32]
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat(timespec="seconds")


def mentioned(text, limit=5):
    """Full calendar dates written in the text, as sorted unique 'YYYY-MM-DD' strings."""
    out = set()
    for rx, order in _PATTERNS:
        for m in rx.finditer(text or ""):
            parts = dict(zip(order, m.groups()))
            try:
                mon = int(parts["m"]) if parts["m"].isdigit() else _MONTHS[parts["m"][:3].lower()]
                out.add(date(int(parts["y"]), mon, int(parts["d"])).isoformat())
            except (ValueError, KeyError):
                pass
    return sorted(out)[:limit]


def old_event(published_at, mentioned_dates, days=30):
    """The latest date the text mentions, if every mentioned date is more than `days` before publication."""
    if not published_at or not mentioned_dates:
        return None
    try:
        pub = date.fromisoformat(published_at[:10])
        latest = date.fromisoformat(max(mentioned_dates))
    except ValueError:
        return None
    return latest.isoformat() if (pub - latest).days > days else None
