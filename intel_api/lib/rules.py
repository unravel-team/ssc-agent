"""The dependency rules: ALLOW / HOLD / BLOCK from the evidence for one package version. Deterministic: AI never
overrides them. One copy, used everywhere: the sources API's scan pipeline (engine/assess.py), the gatekeeper,
the install guardrail and the hooks.

    decide(dep, signals, cooling_hours, internal) -> (verdict, reasons)
    full_evidence(evidence)                       the complete evidence shape decide() expects (the API leaves
                                                  out empty fields)
"""

from .packages import source_may_block

# a version newer than this is held for review: a malicious release is usually caught and pulled within a day or two
COOLING_HOURS = 48

# news articles and community posts are unverified: a package is held for them only when this many separate
# reports agree; one report alone is not evidence
MIN_REPORTS = 2

FINDING_DEFAULTS = {
    "summary": "",
    "severity": None,
    "cves": [],
    "fixed_in": [],
    "malicious": False,
    "malicious_other_version": False,
    "in_kev": False,
    "in_vulncheck_kev": False,
    "epss_max": 0.0,
    "versions": [],
    "url": "",
    "published": None,
}


def full_evidence(ev):
    """The API leaves out empty fields; give the rules the complete shape they expect."""
    reg = {"exists": False, **(ev.get("registry") or {})}
    return {
        **ev,
        "registry": reg,
        "typosquat_of": ev.get("typosquat_of") or [],
        "social": ev.get("social") or [],
        "vulns": [{**FINDING_DEFAULTS, **v} for v in ev.get("vulns") or []],
    }


def decide(dep, s, cooling_hours, internal):
    """Deterministic policy. Returns (verdict, reasons). AI never overrides this."""
    block, hold = [], []
    r = s["registry"]
    # internal names may be qualified by ecosystem ("npm:emails", "pypi:app"); plain names match both
    eco = "npm" if dep["ecosystem"] == "npm" else "pypi"
    is_internal = dep["name"] in internal or f"{eco}:{dep['name']}" in internal
    if is_internal and r["exists"] and not r.get("unverified"):
        block.append("Internal package name exists on the PUBLIC registry (dependency confusion)")
    elif is_internal:
        hold.append("Internal package: ensure it resolves only from the private registry and reserve the name publicly")
    if r.get("unverified"):
        hold.append(f"Could not verify this package: {r['unverified']}. Re-check when the registry is reachable")
    elif not r["exists"] and not is_internal:
        block.append("Package does not exist on the registry (possible AI hallucination / slopsquatting target)")
    if r["exists"] and dep["version"] and r.get("version_exists") is False:
        block.append(
            f"Version {dep['version']} is not available on the registry (removed or never published; often pulled after a compromise)"
        )
    if r.get("version_yanked"):
        block.append(f"Version {dep['version']} was yanked by the maintainers")
    mal = [v for v in s["vulns"] if v["malicious"]]
    strong = [v for v in mal if source_may_block(v["source"])]
    weak = [v for v in mal if v not in strong]
    if strong:
        block.append(
            f"Listed as malicious: {', '.join(v['id'] for v in strong[:3])} ({', '.join(sorted({v['source'] for v in strong}))})"
        )
    if weak:  # reported by sources not rated high enough to block on their own
        hold.append(
            f"Reported malicious by {', '.join(sorted({v['source'] for v in weak}))} ({', '.join(v['id'] for v in weak[:3])}); "
            "not confirmed by a source that can block - verify"
        )
    if s["typosquat_of"] and r["exists"]:
        # under a year old: block; older ones are held for review (small, stable packages have few releases)
        young = (r.get("first_release_days") or 9999) < 365
        (block if young else hold).append(f"Name is very close to popular package(s): {', '.join(s['typosquat_of'])}")
    elif s["typosquat_of"] and not r["exists"] and not is_internal and not r.get("unverified"):
        hold.append(f"Unregistered name close to {', '.join(s['typosquat_of'])}: attackers could register it")
    other = [v for v in s["vulns"] if v.get("malicious_other_version")]
    if other:
        hold.append(
            f"Other versions of this package were malicious ({other[0]['id']}: {', '.join(other[0]['versions'][:3])}); pin exactly and verify"
        )
    real = [v for v in s["vulns"] if not v["malicious"] and not v.get("malicious_other_version")]
    if any(v["in_kev"] for v in real):
        block.append("Has a vulnerability on CISA's Known Exploited Vulnerabilities list")
    vc_only = [v for v in real if v.get("in_vulncheck_kev") and not v["in_kev"]]
    if vc_only:
        hold.append(f"{len(vc_only)} vulnerability(ies) exploited in the wild per VulnCheck KEV (not yet on CISA KEV)")
    hi = [v for v in real if (v.get("severity") or "").upper() in ("HIGH", "CRITICAL")]
    if hi:
        hold.append(
            f"{len(hi)} high/critical vulnerabilities (of {len(real)} total); upgrade available"
            if any(v["fixed_in"] for v in hi)
            else f"{len(hi)} high/critical vulnerabilities"
        )
    elif real:
        hold.append(f"{len(real)} known vulnerabilities (moderate/low)")
    if r.get("install_scripts"):
        hold.append("Runs install-time scripts: " + ", ".join(r["install_scripts"]))
    if r.get("version_age_days") is not None and r["version_age_days"] * 24 < cooling_hours:
        hold.append(f"Version is only {r['version_age_days'] * 24:.0f}h old (cooling-off is {cooling_hours}h)")
    if r.get("deprecated"):
        hold.append("Version is deprecated: " + str(r["deprecated"])[:100])
    # live intel from the threat-intel agent (run after it, in wave B). These notices are written by an AI
    # agent from news articles, so they can only HOLD; a BLOCK needs a curated source (OSV malicious, KEV, ...).
    for n in s.get("notices", []):
        why = f"Breach notice '{n['id']}' ({n.get('confidence', '?')} confidence) names this package"
        if n.get("hits_version"):
            hold.append(why + f" and version {dep['version']} (URGENT: confirm against an advisory)")
        else:
            hold.append(
                why
                + f" (affected: {', '.join(map(str, n.get('versions') or ['unknown']))[:60]}); our version is not listed"
            )
    # news and community posts are unverified on their own: they count only when at least two separate reports
    # (different links) say the same about this package. A lone article or post, and posts about other versions,
    # stay in the evidence (and its links) but do not change the verdict.
    news = s.get("news", [])
    mine = [h for h in s["social"] if "title" in h and not h.get("other_version")]
    reports = {x.get("url") or x.get("title") for x in news + mine}
    if len(reports) >= MIN_REPORTS:
        srcs = sorted({x.get("source") or "?" for x in news + mine})
        hold.append(
            f"{len(reports)} separate reports of security problems ({', '.join(srcs[:3])}); verify against advisories"
        )
    verdict = "BLOCK" if block else ("HOLD" if hold else "ALLOW")
    return verdict, block + hold
