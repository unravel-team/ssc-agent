"""Hacker News stories (Algolia search API)."""

from .._paths import L
from .base import SearchSource
from .registry import register


@register
class HackerNews(SearchSource):
    key = "hacker_news"
    kind = "social"
    order = 10

    def search(self, term=None, query=None, days=120):
        return L.social_hn(term or query, days)
