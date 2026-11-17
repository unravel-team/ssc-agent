"""Finds every source class under intel_api/sources/ and gives the rest of the code one way to use them.

Adding a source = adding a file here with a class decorated with @register (see intel_api/README.md, "Adding a source").
Files whose name starts with "_" are not loaded. Extra folders can be added with SSC_INTEL_SOURCES_PATH
(os.pathsep-separated), for sources you keep outside this repo.
"""

import importlib
import importlib.util
import os
import pkgutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from .._paths import L
from .base import FeedSource, PackageSource, SearchSource, Source

_CLASSES = []
_INSTANCES = None
_LOCK = threading.Lock()
SKIP = {"base", "registry"}


def register(cls):
    """Class decorator: make a source available to the service, the agents and the hooks."""
    if not issubclass(cls, Source):
        raise TypeError(f"{cls.__name__} is not a Source")
    if any(c.key == cls.key and c is not cls for c in _CLASSES):
        raise ValueError(f"two sources use key '{cls.key}'")
    if cls not in _CLASSES:
        _CLASSES.append(cls)
    return cls


def _discover():
    here = os.path.dirname(os.path.abspath(__file__))
    for m in pkgutil.iter_modules([here]):
        if not m.name.startswith("_") and m.name not in SKIP:
            importlib.import_module(f"{__package__}.{m.name}")
    for extra in filter(None, (os.environ.get("SSC_INTEL_SOURCES_PATH") or "").split(os.pathsep)):
        for m in pkgutil.iter_modules([extra]):
            if m.name.startswith("_"):
                continue
            spec = importlib.util.spec_from_file_location(
                f"ssc_extra_sources.{m.name}", os.path.join(extra, m.name + ".py")
            )
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)


def all_sources():
    """{key: instance}, in run order."""
    global _INSTANCES
    with _LOCK:
        if _INSTANCES is None:
            _discover()
            _INSTANCES = {c.key: c() for c in sorted(_CLASSES, key=lambda c: (c.order, c.key))}
    return _INSTANCES


def reload():
    """Re-read config and re-create sources (tests, or after editing intel_api/config/sources.json)."""
    global _INSTANCES
    with _LOCK:
        _INSTANCES = None
    return all_sources()


def get(key):
    return all_sources().get(key)


def feeds(enabled_only=True):
    return {k: s for k, s in all_sources().items() if isinstance(s, FeedSource) and (s.enabled or not enabled_only)}


def package_sources(enabled_only=True):
    return [s for s in all_sources().values() if isinstance(s, PackageSource) and (s.enabled or not enabled_only)]


def searchers(kind, enabled_only=True):
    return [
        s
        for s in all_sources().values()
        if isinstance(s, SearchSource) and s.kind == kind and (s.enabled or not enabled_only)
    ]


# ---------------------------------------------------------------- used by the engine, the gatekeeper and the collector
def package_findings(dep, exclude_ids=()):
    """Findings from every enabled PackageSource for one package version (failures are recorded, not raised)."""
    out, seen = [], set(exclude_ids)
    for s in package_sources():
        if dep["ecosystem"] not in s.ecosystems:
            continue
        try:
            for f in s.check(dep) or []:
                if f["id"] not in seen:
                    seen.add(f["id"])
                    out.append(f)
        except Exception as e:  # noqa: BLE001 - one source failing must not sink the check; recorded in its health
            s.failed(e)
    return out


def prepare_packages(deps):
    for s in package_sources():
        try:
            s.prepare([d for d in deps if d["ecosystem"] in s.ecosystems])
        except Exception as e:  # noqa: BLE001 - recorded in the source's health
            s.failed(e)


def _social_filter(posts, term, days):
    """Keep posts that name the term AND use a security word, within the window, one per URL."""
    cut = (L.NOW - timedelta(days=days)).date().isoformat()
    seen, out = set(), []
    for p in posts:
        if (
            p.get("url") in seen
            or not L.mentions(term, p.get("title", ""))
            or not L.SEC_WORDS.search(p.get("title", ""))
            or (p.get("date") and str(p["date"])[:10] < cut)
        ):
            continue
        seen.add(p.get("url"))
        out.append(p)
    return out


POST_FILTERS = {"social": lambda items, term, query, days: _social_filter(items, term or query, days)}


def search(kind, term=None, query=None, days=45, workers=6):
    """Ask every enabled source of this kind, merge the results in source order, apply the kind's filter."""
    for s in searchers(kind, enabled_only=False):
        if not s.enabled:
            L.disable(s.label, s.disabled_reason)  # shows up in coverage as "needs credentials" / "off"
    srcs = searchers(kind)
    if not srcs:
        return []

    def one(s):
        try:
            return s.search(term=term, query=query, days=days) or []
        except Exception as e:  # noqa: BLE001 - recorded in the source's health; the other sources still answer
            s.failed(e)
            return []

    with ThreadPoolExecutor(max_workers=min(workers, len(srcs))) as pool:
        items = [i for batch in pool.map(one, srcs) for i in batch]
    f = POST_FILTERS.get(kind)
    return f(items, term, query, days) if f else items


# Sources the gatekeeper's core package evidence calls directly (gatekeeper.registry/typosquat/vulns).
# They work as before; moving them into PackageSource classes is possible later without changing callers.
BUILTIN_EVIDENCE = {
    "osv": "package vulns + malware history",
    "ghsa": "package advisories",
    "ossf_malicious_packages": "malware",
    "cisa_kev": "exploited CVEs",
    "vulncheck_kev": "exploited CVEs",
    "epss": "exploit likelihood",
    "top_pypi": "typosquat reference",
    "top_npm": "typosquat reference",
    "npm_downloads": "typosquat reference",
    "pypi_downloads": "typosquat reference",
}


def describe():
    """Registered sources, plus config entries used inside the gatekeeper's core evidence or not connected yet."""
    have = all_sources()
    out = {k: s.describe() for k, s in have.items()}
    for k, d in out.items():
        if k in BUILTIN_EVIDENCE:
            d["capabilities"] = d["capabilities"] + ["package (built in)"]
    for k, c in L.CONFIG["sources"].items():
        if k in out:
            continue
        builtin = k in BUILTIN_EVIDENCE
        out[k] = {
            "key": k,
            "label": c.get("label", k),
            "capabilities": ["package (built in)"] if builtin else [],
            "enabled": c.get("enabled", True),
            "disabled_reason": None if c.get("enabled", True) else (c.get("disabled_reason") or "disabled in config"),
            "reliability": c.get("reliability"),
            "may_block": L.may_block(c.get("label", k)),
            "in_config": True,
            "module": "gatekeeper.py" if builtin else None,
            "note": "used by the gatekeeper's core evidence: " + BUILTIN_EVIDENCE[k]
            if builtin
            else "listed in config, no source class yet",
        }

    def order(kv):  # own source classes first, then built-in evidence, then config entries with no class
        module = kv[1]["module"]
        return (0 if module and module != "gatekeeper.py" else 1 if module else 2, kv[0])

    return dict(sorted(out.items(), key=order))
