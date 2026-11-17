"""X (Twitter) recent search (needs an X API plan with search)."""

from .._paths import L
from .base import SearchSource
from .registry import register


@register
class X(SearchSource):
    key = "x"
    kind = "social"
    order = 40
    requires_env = ("X_BEARER_TOKEN",)

    def search(self, term=None, query=None, days=120):
        return L.social_x(term or query)
