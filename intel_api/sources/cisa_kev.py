"""CISA Known Exploited Vulnerabilities: proof that a CVE is being exploited in the wild."""

from .base import FeedSource
from .registry import register

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@register
class CisaKev(FeedSource):
    key = "cisa_kev"
    order = 20

    def pull(self, state):
        d = self.fetch(URL, timeout=40)
        if not d or "vulnerabilities" not in d:
            raise RuntimeError("CISA KEV feed unavailable")
        out = []
        for v in d["vulnerabilities"]:
            cve = v["cveID"]
            out.append(
                self.signal(
                    "exploited",
                    f"{cve}: {v.get('vendorProject', '')} {v.get('product', '')} - {v.get('vulnerabilityName', '')}",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    key=cve,
                    subject={"type": "cve", "name": cve, "vendor": v.get("vendorProject"), "product": v.get("product")},
                    published_at=v.get("dateAdded"),
                    data={
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "due_date": v.get("dueDate"),
                        "ransomware": v.get("knownRansomwareCampaignUse"),
                        "summary": (v.get("shortDescription") or "")[:300],
                    },
                )
            )
        return out, {"catalog_version": d.get("catalogVersion"), "count": len(out)}
