"""Mastodon: security hashtag timelines (config: mastodon.tags), matched locally against the term.

The timelines are one shared pool, refreshed every 15 minutes. Built under a lock, because the API
and the agents search many terms in parallel and must never see a half-built pool.
"""

import threading
import time

from .._paths import L
from .base import SearchSource
from .registry import register

POOL_TTL = 900
_LOCK = threading.Lock()
_POOL = {"at": 0.0, "posts": []}


@register
class Mastodon(SearchSource):
    key = "mastodon"
    kind = "social"
    order = 50

    def pool(self):
        with _LOCK:
            if time.time() - _POOL["at"] > POOL_TTL:
                posts = []
                for t in L.MASTODON_TAGS:
                    for s in self.fetch(f"https://mastodon.social/api/v1/timelines/tag/{t}?limit=40") or []:
                        posts.append(
                            {
                                "source": "Mastodon",
                                "title": L.strip_html(s.get("content"))[:240],
                                "url": s.get("url"),
                                "date": (s.get("created_at") or "")[:10],
                                "engagement": s.get("reblogs_count"),
                                "author": (s.get("account") or {}).get("acct"),
                            }
                        )
                _POOL.update(at=time.time(), posts=posts)
            return _POOL["posts"]

    def search(self, term=None, query=None, days=120):
        t = term or query
        return [p for p in self.pool() if L.mentions(t, p["title"])]
