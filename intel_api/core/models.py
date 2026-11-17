"""The one record type every source is turned into: a signal."""

import hashlib
import json
from datetime import datetime, timezone

from .._paths import L
from . import dates

KINDS = ("malicious", "vuln", "exploited", "breach", "news", "social", "ca_distrust")
SUBJECTS = ("package", "vendor", "cve", "ca", "action", "none")
AI_MAX_RELIABILITY = 3  # AI-extracted records (breach notices from the threat-intel agent): HOLD at most


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def signal(
    source,
    kind,
    title,
    url="",
    subject=None,
    published_at=None,
    data=None,
    key=None,
    reliability=None,
    may_block=None,
    ai_extracted=False,
):
    """Build a signal dict. `key` is what makes it unique within the source (advisory id, url, ...).
    ai_extracted: an AI wrote this record from `source` (e.g. a breach notice from an article). Its rating is capped
    so it can HOLD at most, never BLOCK, and data.extracted_by says who wrote it."""
    assert kind in KINDS, kind
    subject = subject or {"type": "none"}
    rel = reliability if reliability is not None else L.reliability(source)
    if ai_extracted:
        rel = min(rel or AI_MAX_RELIABILITY, AI_MAX_RELIABILITY)
        data = {**(data or {}), "extracted_by": "threat-intel agent"}
    raw = f"{source}|{kind}|{key or url or title}|{subject.get('ecosystem', '')}|{(subject.get('name') or '').lower()}"
    return {
        "id": hashlib.sha256(raw.encode()).hexdigest()[:20],
        "source": source,
        "reliability": rel,
        "may_block": (bool(L.may_block(source)) if may_block is None else bool(may_block)) and not ai_extracted,
        "kind": kind,
        "subject": subject,
        "title": (title or "")[:400],
        "url": url or "",
        "published_at": dates.normalize(published_at),
        "data": _with_dates(data or {}, title),
    }


def _with_dates(data, title):
    """Add the event dates mentioned in the title/summary (news, social, breach text)."""
    found = dates.mentioned(f"{title or ''} {data.get('summary') or ''}")
    if found:
        data = {**data, "mentioned_dates": found}
    return data


def dumps(o):
    return json.dumps(o, default=str, separators=(",", ":"))
