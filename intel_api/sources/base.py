"""Base classes for sources. A source is one class in one file under intel_api/sources/.

Pick the base class (or several) for what the source can do:

  FeedSource      pulled whole on a schedule (its speed: urgent / regular / slow); returns signals to store.
                  e.g. CISA KEV, OSV's new-malware list, RSS feeds, a vendor's malware list.
  PackageSource   asked about one package version during a check; returns findings that join
                  the gatekeeper's evidence, so they affect verdicts (within the source's rating).
  SearchSource    asked to search for a term or query; kind = "news", "social" or "nvd".

Everything else comes from the base class:
  - settings from the source's entry in intel_api/config/sources.json (label, enabled, reliability,
    may_block, speed), with the class's `defaults` used when there is no entry;
  - self.fetch(): HTTP with the shared disk cache, per-source health tracking and the
    'enabled' switch from the config;
  - self.signal() / self.finding(): records stamped with this source's label and rating.
"""

import os
from typing import ClassVar

from .._paths import L
from ..core.models import signal as _signal


class Source:
    key = None  # entry in intel_api/config/sources.json "sources"; required
    label = None  # display name; default: the config entry's label, else the key
    requires_env = ()  # env vars the source needs; missing ones disable it with a clear reason
    defaults: ClassVar[dict] = {}  # settings used when the config has no entry (reliability, may_block, speed, ...)
    order = 100  # run order within a kind (lower first); keeps merged results stable

    def __init__(self):
        if not self.key:
            raise TypeError(f"{type(self).__name__} must set key")
        self.config = {
            "enabled": True,
            "reliability": 2,
            "may_block": False,
            **self.defaults,
            **(L.CONFIG["sources"].get(self.key) or {}),
        }
        self.label = self.label or self.config.get("label") or self.key
        self.in_config = self.key in L.CONFIG["sources"]

    # ---------------------------------------------------------------- settings
    @property
    def missing_env(self):
        return [e for e in self.requires_env if not os.environ.get(e)]

    @property
    def enabled(self):
        return bool(self.config.get("enabled", True)) and not self.missing_env

    @property
    def disabled_reason(self):
        if not self.config.get("enabled", True):
            return self.config.get("disabled_reason") or "disabled in intel_api/config/sources.json"
        if self.missing_env:
            return "set " + " and ".join(self.missing_env)
        return None

    @property
    def reliability(self):
        r = L.reliability(self.label) if self.in_config else None
        return r if r is not None else self.config.get("reliability")

    @property
    def may_block(self):
        """Only sources rated at or above the policy's block threshold may BLOCK on their own."""
        need = L.CONFIG.get("policy", {}).get("block_min_reliability", 5)
        return bool(self.config.get("may_block")) and (self.reliability or 0) >= need

    @property
    def speed(self):
        """Feeds only: how often it is pulled (urgent / regular / slow, see "speeds" in the config)."""
        return self.config.get("speed") or "regular"

    @property
    def every_seconds(self):
        return L.speed_seconds(self.speed)

    @property
    def capabilities(self):
        caps = []
        if isinstance(self, FeedSource):
            caps.append("feed")
        if isinstance(self, PackageSource):
            caps.append("package")
        if isinstance(self, SearchSource):
            caps.append("search:" + self.kind)
        return caps

    # ---------------------------------------------------------------- helpers
    def fetch(self, url, **kw):
        """GET/POST this source. Returns parsed JSON (or text with raw=True), or None on failure."""
        return L.fetch(url, self.label, **kw)

    def ok(self):
        L._mark(self.label, True)

    def failed(self, err):
        L._mark(self.label, False, err)

    def signal(self, kind, title, **kw):
        kw.setdefault("reliability", self.reliability)
        kw.setdefault("may_block", self.may_block)
        return _signal(self.label, kind, title, **kw)

    def describe(self):
        return {
            "key": self.key,
            "label": self.label,
            "capabilities": self.capabilities,
            "enabled": self.enabled,
            "disabled_reason": self.disabled_reason,
            "reliability": self.reliability,
            "may_block": self.may_block,
            **({"speed": self.speed, "every_seconds": self.every_seconds} if isinstance(self, FeedSource) else {}),
            "in_config": self.in_config,
            "module": type(self).__module__.rsplit(".", 1)[-1],
        }


class FeedSource(Source):
    def pull(self, state):
        """-> (signals, new_state). `state` is what this source returned last time ({} on the first run).
        Raise an exception if the pull failed, so the previous state is kept and health shows the error."""
        raise NotImplementedError


class PackageSource(Source):
    ecosystems = ("PyPI", "npm")

    def prepare(self, deps):
        """Optional: called once before checking a batch (e.g. load a list, batch an API call)."""

    def check(self, dep):
        """dep = {ecosystem, name, version}. -> list of findings (use self.finding())."""
        raise NotImplementedError

    def finding(
        self,
        id,
        summary="",
        malicious=False,
        other_version=False,
        severity=None,
        cves=(),
        fixed_in=(),
        versions=(),
        url="",
        published=None,
        in_kev=False,
    ):
        """A finding in the same shape as the gatekeeper's own evidence, stamped with this source's label.
        The gatekeeper's rules read `source` to apply this source's rating (e.g. malware from a source that
        may not block becomes a HOLD)."""
        return {
            "id": id,
            "source": self.label,
            "cves": list(cves),
            "summary": (summary or "")[:160],
            "severity": severity or ("CRITICAL" if malicious else None),
            "malicious": bool(malicious and not other_version),
            "malicious_other_version": bool(malicious and other_version),
            "fixed_in": list(fixed_in)[:3],
            "in_kev": bool(in_kev),
            "url": url,
            "versions": list(versions)[:20],
            "published": published,
        }


class SearchSource(Source):
    kind = None  # "news", "social" or "nvd"

    def search(self, term=None, query=None, days=45):
        """-> list of items {source, title, url, date, ...}. `term` is the name being watched; `query` an
        optional full search query (news). Return [] when there is nothing or the source is unavailable."""
        raise NotImplementedError
