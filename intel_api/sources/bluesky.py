"""Bluesky post search (needs an app password)."""

from .._paths import L
from .base import SearchSource
from .registry import register


@register
class Bluesky(SearchSource):
    key = "bluesky"
    kind = "social"
    order = 30
    requires_env = ("BSKY_HANDLE", "BSKY_APP_PASSWORD")

    def search(self, term=None, query=None, days=120):
        return L.social_bluesky(term or query)
