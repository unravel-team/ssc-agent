"""NVD CVE API 2.0: recent CVEs that mention a keyword (slow without NVD_API_KEY)."""

from .._paths import L
from .base import SearchSource
from .registry import register


@register
class Nvd(SearchSource):
    key = "nvd"
    kind = "nvd"

    def search(self, term=None, query=None, days=120):
        return L.nvd_search(term or query, days)
