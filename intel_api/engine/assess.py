"""Turn lookup results for a scope into verdicts, verified fix versions and a change plan.

    assess(scope, results, lookup) -> assessment

  scope     what a scanner found: packages (each with found_in: project, file, line, text, spec, version, version_from),
            vendors, internal_packages. File paths are relative to the scanned folder; `text` is the dependency's
            line in that file, so the plan can be made without the files (they stay on the laptop).
  results   the lookup of those packages (the /v1/lookup shape: evidence + item rows per package, plus vendors)
  lookup    function(list of (package_manager, name, version)) -> lookup results; used to CHECK fix versions

  verdict   the rules in lib/rules.py on the evidence, plus breach notices and news about the package version
  fix       for anything not ALLOW: a candidate version (the lowest version that fixes every advisory, else the
            latest), checked with the same rules: a fix is "verified" only if that version itself is safe
  edits     exact line edits (requirements*.txt, package.json, pyproject.toml); lockfiles are not edited (the plan
            says which command regenerates them)
  manual    actions no file edit can do (dependency-confusion protection, reviewing install scripts, ...)

Rules decide; nothing here is an AI judgement, and nothing here changes a file.
"""

import re
import urllib.parse

from ..lib.packages import get
from ..lib.rules import COOLING_HOURS, full_evidence
from ..lib.rules import decide as rules_decide

ECO = {"pip": "PyPI", "npm": "npm"}
SEV = {"BLOCK": 0, "HOLD": 1, "ALLOW": 2}
# a fix version is safe when it is not BLOCK and none of its HOLD reasons is about that version itself;
# warnings about OTHER versions, or news/social chatter about the package, don't disqualify it
NOT_SAFE = re.compile(
    r"high/critical|Known Exploited|exploited in the wild|cooling-off|deprecated|install-time scripts|"
    r"not available on the registry|yanked|Breach notice.*and version|Could not verify",
    re.I,
)


def safe_fix(verdict, reasons):
    return verdict not in ("BLOCK", "ERROR") and not any(NOT_SAFE.search(r) for r in reasons)


def vkey(v):
    """Comparable version key: numbers first; pre-releases (1.2.0rc1, 1.2.0-beta) sort below the release."""
    v = str(v or "")
    m = re.match(r"^v?(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((), 1, v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums))
    return (nums, 0 if m.group(2) else 1, m.group(2))


def major(v):
    return vkey(v)[0][0] if vkey(v)[0] else None


def signals_for(r, version):
    """Evidence for the rules: lookup evidence plus breach notices and news about this package version."""
    s = full_evidence(r["evidence"])
    items = r.get("items") or []
    s["notices"] = [
        {
            "id": i["signal_id"],
            "confidence": "medium",
            "versions": [i["version"]] if i.get("version") else [],
            "hits_version": not i.get("version") or i.get("version") == version,
        }
        for i in items
        if i["kind"] == "breach"
    ]
    s["news"] = [
        {"source": i["source"], "title": i["title"], "url": i["url"], "date": i.get("date")}
        for i in items
        if i["kind"] == "news" and (not i.get("version") or i.get("version") == version)
    ]
    return s


def decide(r, internal):
    version = r.get("version") or r.get("resolved_version")
    dep = {"ecosystem": ECO[r["package_manager"]], "name": r["package"], "version": version}
    return rules_decide(dep, signals_for(r, version), COOLING_HOURS, internal)


def fix_target(r, version):
    """Lowest version above the current one that fixes every advisory on it (None if there's nothing to fix)."""
    target = None
    for v in (r.get("evidence") or {}).get("vulns", []):
        if v.get("malicious") or v.get("malicious_other_version"):
            continue
        above = sorted((f for f in v.get("fixed_in") or [] if vkey(f) > vkey(version)), key=vkey)
        if above and (target is None or vkey(above[0]) > vkey(target)):
            target = above[0]
    return target


def declared_in(scope, file, name):
    """Is `name` declared in that file? (from the scope: every package lists the files it was found in)"""
    return any(
        p["name"].lower() == name.lower() and any(f.get("file") == file for f in p.get("found_in") or [])
        for p in scope.get("packages", [])
    )


def edits_for(scope, pkg_scope, r, to_version, new_name=None):
    """Line edits that move every declared spec of this package to to_version (or rename or remove it)."""
    out, notes = [], set()
    old_v = r.get("version") or r.get("resolved_version")
    for loc in pkg_scope.get("found_in", []):
        line = loc.get("text")
        if loc.get("version") != old_v or not loc.get("line") or line is None:
            continue
        new = line
        base = loc["file"].rsplit("/", 1)[-1]
        if new_name:  # typosquat / made-up name -> the real package
            if declared_in(scope, loc["file"], new_name):
                notes.add(f"{new_name} is already declared in {loc['file']}: the misspelled line is removed")
                out.append(
                    {"file": loc["file"], "line": loc["line"], "old": line, "new": None, "project": loc.get("project")}
                )
                continue
            new = re.sub(re.escape(pkg_scope["name"]), new_name, new, count=1)
        if to_version is None:
            new = None  # remove the line
        elif base == "package.json":
            new = re.sub(
                r'("' + re.escape(new_name or pkg_scope["name"]) + r'"\s*:\s*")([\^~]?)[^"]*"',
                lambda m: f'{m.group(1)}{m.group(2)}{to_version}"',
                new,
                count=1,
            )
        elif loc.get("version_from") == "pinned":
            new = re.sub(r"==\s*[^\s;,\"']+", f"=={to_version}", new, count=1)
            if new == line and base == "pyproject.toml":  # Poetry: name = "1.0" or name = {version = "1.0", ...}
                field = r"(version\s*=\s*[\"'])" if "{" in line else r"(=\s*[\"'])"
                new = re.sub(field + r"(?:==)?\s*[0-9][^\"']*([\"'])", rf"\g<1>{to_version}\g<2>", new, count=1)
        else:  # a range resolved by the lockfile: raise the floor
            new2 = re.sub(r">=\s*[^\s;,\"']+", f">={to_version}", new, count=1)
            new = new2 if new2 != new else new
        if loc.get("version_from") == "lockfile":
            notes.add(
                "regenerate the lockfile: "
                + ("uv lock --upgrade-package " if pkg_scope["package_manager"] == "pip" else "bun update ")
                + (new_name or pkg_scope["name"])
            )
        if new != line:
            out.append(
                {"file": loc["file"], "line": loc["line"], "old": line, "new": new, "project": loc.get("project")}
            )
    return out, sorted(notes)


def verify(lookup, candidates, internal):
    """Look each candidate (pm, name, version) up and decide it with the same rules."""
    if not candidates:
        return {}
    out = {}
    for r in lookup(candidates):
        key = (r["package_manager"], r["package"].lower(), r.get("version"))
        resolved = r.get("version") or r.get("resolved_version")
        out[key] = ("ERROR", [r["error"]], resolved) if r.get("error") else (*decide(r, internal), resolved)
    return out


def releases_before(pm, name, version, n=3):
    """The n newest final releases below `version`, from the registry (read-only)."""
    if pm == "pip":
        _, d = get(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json")
        vers = [
            v
            for v, files in ((d or {}).get("releases") or {}).items()
            if files and not all(f.get("yanked") for f in files)
        ]
    else:
        _, d = get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
        vers = list(((d or {}).get("versions") or {}).keys())
    finals = [v for v in vers if re.fullmatch(r"\d+(\.\d+)*", v) and vkey(v) < vkey(version)]
    return sorted(finals, key=vkey, reverse=True)[:n]


def _counts(items):
    c = {}
    for i in items:
        c[i["kind"]] = c.get(i["kind"], 0) + 1
    return c


OTHER_VERSIONS_MALICIOUS = "Other versions of this package were malicious"


def drop_followed_pin_advice(verdict, reasons, found_in):
    """ "Other versions were malicious; pin exactly" is already followed when every place the package is declared pins
    this exact version (which the rules found not malicious itself): drop that reason, and HOLD becomes ALLOW if it
    was the only one. A range could still pull in a bad version, so it keeps the reason."""
    # a lockfile pins the exact version too
    if not found_in or any(f.get("version_from") not in ("pinned", "lockfile") for f in found_in):
        return verdict, reasons
    kept = [x for x in reasons if not x.startswith(OTHER_VERSIONS_MALICIOUS)]
    if verdict == "HOLD" and not kept:
        return "ALLOW", kept
    return verdict, kept


def assess(scope, results, lookup, releases=releases_before):
    internal = set(scope.get("internal_packages") or [])
    by_pkg = {(p["package_manager"], p["name"].lower()): p for p in scope.get("packages", [])}

    assessed, todo = [], []
    for r in results["packages"]:
        version = r.get("version") or r.get("resolved_version")
        if r.get("error"):
            assessed.append(
                {
                    "package": r["package"],
                    "package_manager": r["package_manager"],
                    "version": version,
                    "verdict": "UNKNOWN",
                    "reasons": [f"lookup failed: {r['error']}"],
                }
            )
            continue
        verdict, reasons = decide(r, internal)
        ev, items = r.get("evidence") or {}, r.get("items") or []
        reg = ev.get("registry") or {}
        found_in = [
            {k: f.get(k) for k in ("project", "file", "line", "spec", "version_from", "section", "used")}
            for f in by_pkg.get((r["package_manager"], r["package"].lower()), {}).get("found_in", [])
            if f.get("version") == version
        ]
        verdict, reasons = drop_followed_pin_advice(verdict, reasons, found_in)
        entry = {
            "package": r["package"],
            "package_manager": r["package_manager"],
            "version": version,
            "verdict": verdict,
            "reasons": reasons,
            "latest": reg.get("latest"),
            "findings": _counts(items),
            "malicious": [v["id"] for v in ev.get("vulns", []) if v.get("malicious")],
            "advisories": [
                {
                    k: v.get(k)
                    for k in ("id", "severity", "summary", "fixed_in", "in_kev", "epss_max", "symbols")
                    if v.get(k)
                }
                for v in ev.get("vulns", [])
                if not v.get("malicious") and not v.get("malicious_other_version")
            ][:15],
            "news": [
                {k: i.get(k) for k in ("date", "source", "title", "url")}
                for i in items
                if i["kind"] in ("news", "social", "breach")
            ][:8],
            "malicious_other": [v["id"] for v in ev.get("vulns", []) if v.get("malicious_other_version")],
            "found_in": found_in,
        }
        assessed.append(entry)
        if verdict == "ALLOW":
            continue
        # what would fix it
        eco_internal = ("npm:" if r["package_manager"] == "npm" else "pypi:") + r["package"]
        real = (ev.get("typosquat_of") or [None])[0]
        if r["package"] in internal or eco_internal in internal:
            pass  # our own package: protect the name (manual action), never remove it
        elif real and (not reg.get("exists", True) or any("close to" in x for x in reasons)):
            entry["fix"] = {"kind": "replace", "with": real}
            for v in dict.fromkeys([version, None]):  # same version of the real package if it exists, else its latest
                todo.append((entry, r["package_manager"], real, v))
        elif not reg.get("exists", True) or any("does not exist" in x for x in reasons):
            entry["fix"] = {"kind": "remove", "with": None}
        elif entry["malicious"] or any("not available on the registry" in x or "yanked" in x for x in reasons):
            entry["fix"] = {"kind": "bump", "why": "this version is malicious or pulled"}
            # newest first; if it is too new (cooling-off) or affected, fall back to the last releases before this one
            for v in [reg.get("latest"), *releases(r["package_manager"], r["package"], version)]:
                if v:
                    todo.append((entry, r["package_manager"], r["package"], v))
        else:
            tgt = fix_target(r, version)
            if tgt:
                entry["fix"] = {"kind": "bump", "why": "fixes the advisories on this version"}
                todo.append((entry, r["package_manager"], r["package"], tgt))
                if reg.get("latest") and reg.get("latest") != tgt:
                    todo.append((entry, r["package_manager"], r["package"], reg.get("latest")))  # fallback candidate
    # verify every candidate with the same rules
    cand = sorted({(pm, n, v) for _, pm, n, v in todo}, key=lambda c: (c[0], c[1], vkey(c[2])))
    checked = verify(lookup, cand, internal)
    for entry in assessed:
        fix = entry.get("fix")
        if not fix or fix["kind"] == "remove":
            continue
        tried = []
        for pm, n, v in [(pm, n, v) for e, pm, n, v in todo if e is entry]:
            verdict, reasons, resolved = checked.get((pm, n.lower(), v), ("UNKNOWN", ["not checked"], v))
            if (resolved and resolved != entry["version"]) or n.lower() != entry["package"].lower():
                tried.append(
                    {
                        "package": n,  # the replacement package when the fix is "replace", not the one flagged
                        "version": resolved,
                        "verdict": verdict,
                        "reasons": reasons[:3],
                        "safe": safe_fix(verdict, reasons),
                    }
                )
        good = [t for t in tried if t["safe"]]
        best = (
            good[0]
            if good
            else (sorted(tried, key=lambda t: SEV.get(t["verdict"], -1), reverse=True)[0] if tried else None)
        )
        fix.update(
            {
                "to": best and best["version"],
                "verified": bool(good),
                "candidates_checked": tried,
                "major_upgrade": bool(best and best["version"] and major(best["version"]) != major(entry["version"])),
            }
        )

    # change plan: line edits + manual actions
    edits, manual = [], []
    for entry in assessed:
        fix = entry.get("fix")
        p = by_pkg.get((entry["package_manager"], entry["package"].lower()))
        if not fix or not p:
            if entry["verdict"] != "ALLOW":
                manual.append(
                    {
                        "package": entry["package"],
                        "version": entry["version"],
                        "verdict": entry["verdict"],
                        "action": "review: " + "; ".join(entry["reasons"][:2]),
                    }
                )
            continue
        r = next(
            x
            for x in results["packages"]
            if x["package"] == entry["package"]
            and x["package_manager"] == entry["package_manager"]
            and (x.get("version") or x.get("resolved_version")) == entry["version"]
        )
        if fix["kind"] == "remove":
            es, notes = edits_for(scope, p, r, None)
        elif fix["kind"] == "replace":
            es, notes = edits_for(scope, p, r, fix.get("to"), new_name=fix.get("with"))
        else:
            if not fix.get("to"):
                manual.append(
                    {
                        "package": entry["package"],
                        "version": entry["version"],
                        "verdict": entry["verdict"],
                        "action": "no safe version found automatically; review manually",
                    }
                )
                continue
            es, notes = edits_for(scope, p, r, fix["to"])
        for e in es:
            edits.append(
                {
                    **e,
                    "package": entry["package"],
                    "package_manager": entry["package_manager"],
                    "from": entry["version"],
                    "to": fix.get("to"),
                    "change": fix["kind"],
                    "replace_with": fix.get("with"),
                    "verdict": entry["verdict"],
                    "verified": fix.get("verified", fix["kind"] == "remove"),
                    "major_upgrade": fix.get("major_upgrade", False),
                    "reason": "; ".join(entry["reasons"][:2]),
                }
            )
        for n in notes:
            manual.append(
                {"package": entry["package"], "version": entry["version"], "verdict": entry["verdict"], "action": n}
            )
        if any("dependency confusion" in x or "Internal package" in x for x in entry["reasons"]):
            manual.append(
                {
                    "package": entry["package"],
                    "version": entry["version"],
                    "verdict": entry["verdict"],
                    "action": "resolve this name only from the private registry (scoped registry / index-url) and reserve it publicly",
                }
            )

    return {
        "summary": {v: sum(e["verdict"] == v for e in assessed) for v in ("BLOCK", "HOLD", "ALLOW", "UNKNOWN")},
        "packages": sorted(assessed, key=lambda e: (SEV.get(e["verdict"], -1), e["package"])),
        "vendors": [
            {
                "vendor": v["vendor"],
                "count": v["count"],
                "records": [
                    {k: s.get(k) for k in ("published_at", "kind", "source", "title", "url")} for s in v["signals"][:8]
                ],
            }
            for v in results.get("vendors", [])
        ],
        "edits": edits,
        "manual": manual,
    }


def diff_text(edits, only_verified=True):
    """A unified-diff view of the planned edits, one hunk per edited line (made from the line text the scanner sent)."""
    out, by_file = [], {}
    for e in edits:
        if only_verified and not e.get("verified"):
            continue
        by_file.setdefault(e["file"], []).append(e)
    for f, es in sorted(by_file.items()):
        out += [f"--- a/{f}", f"+++ b/{f}"]
        for e in sorted(es, key=lambda e: e["line"]):
            if e["new"] is None:
                out += [f"@@ -{e['line']},1 +{e['line']},0 @@", f"-{e['old']}"]
            else:
                out += [f"@@ -{e['line']},1 +{e['line']},1 @@", f"-{e['old']}", f"+{e['new']}"]
    return "\n".join(out) + ("\n" if out else "")
