"""Security news RSS/Atom feeds. Add a feed by adding it to news_rss.feeds in intel_api/config/sources.json."""

from .._paths import L
from ..core.models import signal
from .base import FeedSource
from .registry import register


@register
class NewsRss(FeedSource):
    key = "news_rss"
    order = 40

    def pull(self, state):
        items = L.news_feeds()
        if not items:
            raise RuntimeError("no news feed returned items")
        # each feed keeps its own label ("News: <feed>") so per-feed reliability from the config applies
        return [
            signal(
                "News: " + i["source"],
                "news",
                i["title"],
                url=i["url"],
                key=i["url"] or i["title"],
                published_at=i["date"].isoformat() if i.get("date") else None,
                data={"summary": (i.get("summary") or "")[:400]},
            )
            for i in items
            if i.get("url") or i.get("title")
        ], {"items": len(items)}
