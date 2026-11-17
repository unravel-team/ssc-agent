"""Certificate authorities found on a laptop: are they distrusted, reported compromised, or not public at all?

    check_cas(store, cas, files, search) -> [{ca, status, reasons, evidence, files, in_mozilla_store}]

  distrusted  removed from Mozilla's trusted roots (a ca_distrust record): replace it
  reported    security news in the last year says it was compromised, revoked or is being distrusted: check it
  private     not in Mozilla's trusted roots: fine for a company's own CA, a risk for anything else
  ok          a publicly trusted root with nothing reported

Uses what the server already collects: Mozilla's root store (daily) and news (a CA nobody has searched for yet
is searched once, then kept current by the background jobs). Rules only; no AI.
"""

import re
from datetime import datetime, timedelta, timezone

from .._paths import L

# words that say nothing about which CA it is ("eMudhra Technologies Limited" -> "eMudhra")
GENERIC = {
    "technologies",
    "technology",
    "limited",
    "ltd",
    "inc",
    "llc",
    "corp",
    "corporation",
    "co",
    "company",
    "gmbh",
    "sa",
    "ag",
    "plc",
    "trust",
    "services",
    "group",
    "holdings",
    "the",
    "of",
    "ca",
    "certification",
    "authority",
    "pvt",
    "private",
    "root",
    "global",
    "international",
    "networks",
    "solutions",
}
DISTRUST = re.compile(
    r"distrust|untrust|revok|compromis|remov|mis-?issu|cracked|key (?:leak|exposure)|blocked|incident|breach", re.I
)
STATUS_ORDER = {"distrusted": 0, "reported": 1, "private": 2, "ok": 3}


def key_term(org):
    words = re.findall(r"[\w\-]+", org or "")
    keep = [w for w in words if w.lower() not in GENERIC and len(w) > 2]
    return keep[0] if keep else (org or "").strip()


def check_cas(store, cas, files=None, search=None, days=365):
    roots = ((store.source_state("mozilla_ca_store") or {}).get("state") or {}).get("roots") or {}
    cut = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    by_ca = {}
    for f in files or []:
        by_ca.setdefault(f.get("ca"), []).append({k: f.get(k) for k in ("project", "file")})
    out = []
    for org in cas:
        term = key_term(org)
        if search:
            search(term)
        recs = [
            r
            for r in store.query(kinds=["ca_distrust", "news", "breach"], published_since=cut, limit=5000)
            if L.mentions(term, r["title"]) and (r["kind"] == "ca_distrust" or DISTRUST.search(r["title"]))
        ]
        removed = [r for r in recs if r["kind"] == "ca_distrust"]
        in_mozilla = any(L.mentions(term, label) for label in roots.values()) if roots else None
        if removed:
            status, reasons = "distrusted", [f"Removed from Mozilla's trusted roots: {removed[0]['title']}"]
        elif recs:
            status, reasons = (
                "reported",
                [f"{len(recs)} report(s) in the last year of a compromise, revocation or distrust"],
            )
        elif in_mozilla is False:
            status, reasons = (
                "private",
                ["Not in Mozilla's trusted roots: fine for your company's own CA, otherwise check where it came from"],
            )
        else:
            status, reasons = "ok", []
        recs.sort(key=lambda r: r.get("published_at") or "", reverse=True)
        out.append(
            {
                "ca": org,
                "status": status,
                "reasons": reasons,
                "in_mozilla_store": in_mozilla,
                "files": by_ca.get(org, []),
                "evidence": [
                    {
                        "title": r["title"],
                        "url": r["url"],
                        "date": (r.get("published_at") or "")[:10],
                        "source": r["source"],
                    }
                    for r in recs[:3]
                ],
            }
        )
    return sorted(out, key=lambda c: (STATUS_ORDER[c["status"]], c["ca"].lower()))
