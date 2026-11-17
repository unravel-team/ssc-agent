"""Is a record about something we track? Used to decide what gets stored (feeds and searches) and to prune.

Tracked = the packages, vendors, stack and certificate authorities in config/scope.json, plus every package
someone has looked up through the API (it has stored evidence).

  package records (malware feed, advisories)             the package is tracked
  CVE records (CISA KEV, NVD)                                    the CVE is on a tracked package, or the vendor /
                                                                 product names a tracked vendor or stack component
  CA distrust                                                    the CA is in the scope
  news and social posts                                          they name a tracked package or vendor (same rules
                                                                 as the items table), or a tracked CA
  breach notices (pushed by the threat-intel agent)              always kept
"""

from .._paths import L
from ..core import scope as scope_mod
from ..lib import packages as P
from . import index as indexer

GENERIC = {"github", "gitlab", "google", "amazon", "microsoft", "azure", "docker", "apple", "cloudflare", "cloud"}


def _specific(term):
    """Long and specific enough to match text on its own ("Railway" yes; "AWS", "github" no)."""
    return len(term) >= 4 and term not in GENERIC


class Relevance:
    def __init__(self, store, scope=None):
        self.scope = scope or scope_mod.load(store)
        tracked = set(self.scope.packages) | store.evidence_packages()
        self.packages = {(eco, n.lower()) for eco, n in tracked}
        self.watched_pkgs = {k: v["name"] for k, v in self.scope.packages.items()}
        for eco, n in tracked:
            self.watched_pkgs.setdefault((eco, n.lower()), n)
        self.vendors = {t.lower(): v["name"] for v in self.scope.vendors for t in v["terms"]}
        self.vendor_terms = [t for t in self.vendors if _specific(t)]
        self.stack_terms = [x.lower() for x in self.scope.stack if _specific(x.lower())]
        self.cas = [c.split()[0].lower() for c in self.scope.cas]
        self.cves = set()
        for s in store.query(kinds=["vuln", "exploited", "malicious"], subject_type="package", limit=100000):
            self.cves |= set((s["data"] or {}).get("cves") or [])

    def keep(self, sig):
        sub, kind = sig.get("subject") or {}, sig["kind"]
        t = sub.get("type")
        if kind == "breach":
            return True
        if t == "package":
            return (sub.get("ecosystem"), (sub.get("name") or "").lower()) in self.packages
        if t == "cve":
            if sub.get("name") in self.cves:
                return True
            # our vendors must be the CVE's vendor ("Sentry" is not "Ivanti Sentry"); stack components match the product
            vendor, product = sub.get("vendor") or "", sub.get("product") or ""
            term = (sig.get("data") or {}).get("term") or ""  # NVD results: found by searching this term
            return (
                any(L.mentions(t, vendor) for t in self.vendor_terms)
                or any(L.mentions(t, f"{vendor} {product}") for t in self.stack_terms)
                or (bool(term) and (term.lower() in self.vendors or term.lower() in self.stack_terms))
            )
        if t == "ca":
            return any(c in (sub.get("name") or "").lower() for c in self.cas)
        if kind == "social" and (sig.get("data") or {}).get("term"):
            return self.social_about(sig["title"], sig["data"]["term"])
        if kind in ("news", "social"):
            return self.mentions_scope(
                sig["title"], (sig.get("data") or {}).get("summary") or "", sig.get("source", "")
            )
        return False

    def social_about(self, title, term):
        """A post found by searching a tracked term: the same rule the gatekeeper uses for social posts (it names the
        term, uses a security word, and an ordinary-word name needs package context)."""
        t = term.lower()
        if t not in self.vendors and not any(n == t for _, n in self.packages):
            return False
        if not (L.mentions(term, title) and L.SEC_WORDS.search(title)):
            return False
        return t in self.vendors or not P.common_word(term) or bool(P.PKG_CONTEXT.search(title))

    def mentions_scope(self, title, summary="", source=""):
        if source == "News: Google News":  # "<headline> - <Publisher>"; summary repeats it
            title, summary = indexer.GOOGLE_PUBLISHER.sub("", title), ""
        if any(
            m
            for m in indexer.extract(title, summary, "", self.watched_pkgs, self.vendors)
            if (m["subject_type"] == "package" and (m["ecosystem"], m["name"].lower()) in self.packages)
            or m["subject_type"] == "vendor"
        ):
            return True
        low = title.lower()
        return any(c in low for c in self.cas) and "certificat" in f"{low} {summary.lower()}"
