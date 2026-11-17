"""oss-security mailing list: early warnings, often before a CVE or advisory exists."""

from .._paths import L
from .base import FeedSource
from .registry import register


@register
class OssSecurity(FeedSource):
    key = "oss_security"
    order = 30

    def pull(self, state):
        items = L.oss_security(days=45)
        return [
            self.signal(
                "news",
                i["title"],
                url=i["url"],
                key=i["url"] or i["title"],
                published_at=i["date"].isoformat() if i.get("date") else None,
                data={"summary": (i.get("summary") or "")[:400], "early_warning": True},
            )
            for i in items
        ], {"items": len(items)}
