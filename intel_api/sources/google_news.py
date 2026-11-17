"""Google News search (RSS). Used for vendor/package breach news beyond the fixed RSS feeds."""

from .._paths import L
from .base import SearchSource
from .registry import register


@register
class GoogleNews(SearchSource):
    key = "google_news"
    kind = "news"

    def search(self, term=None, query=None, days=45):
        return L.google_news(query or term, days)
