"""GitHub issues whose titles report a malicious/compromised package (needs GITHUB_TOKEN at any volume)."""

from .._paths import L
from .base import SearchSource
from .registry import register


@register
class GithubIssues(SearchSource):
    key = "github_issues"
    kind = "social"
    order = 20

    def search(self, term=None, query=None, days=120):
        return L.social_github(term or query)
