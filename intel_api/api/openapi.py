"""OpenAPI 3 description of the sources API (served at GET /v1/openapi.json).
tests/test_intel_api.py checks that every route in routes.ROUTES is described here."""

from .routes import VERSION


def _ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


def _q(name, desc, typ="string", enum=None, example=None):
    p = {"name": name, "in": "query", "required": False, "description": desc, "schema": {"type": typ}}
    if enum:
        p["schema"]["enum"] = enum
    if example is not None:
        p["example"] = example
    return p


def _p(name, desc, example=None):
    p = {"name": name, "in": "path", "required": True, "description": desc, "schema": {"type": "string"}}
    if example is not None:
        p["example"] = example
    return p


def _ok(schema, desc="OK"):
    return {"200": {"description": desc, "content": {"application/json": {"schema": schema}}}}


def _errors(*codes):
    text = {
        "400": "Bad request (see `error`)",
        "401": "Missing or unknown API key",
        "403": "Key's role is too low",
        "404": "Not found",
        "409": "Not in a state that accepts this (e.g. the scan isn't waiting for an advisory)",
        "413": "Too many packages / body too large",
        "502": "Lookup from the sources failed",
        "503": "Not collected yet",
    }
    return {c: {"description": text[c], "content": {"application/json": {"schema": _ref("Error")}}} for c in codes}


def _op(tag, summary, desc, role, params=(), body=None, ok=None, errors=("400", "401", "403")):
    op = {
        "tags": [tag],
        "summary": summary,
        "description": desc + (f"\n\n**Role:** `{role}`" if role else "\n\n**No key needed.**"),
        "parameters": list(params),
        "responses": {**(ok or _ok({"type": "object"})), **_errors(*(errors if role else ()))},
    }
    if role:
        op["x-required-role"] = role
    else:
        op["security"] = []
    if body:
        op["requestBody"] = {"required": True, "content": {"application/json": {"schema": body[0], "example": body[1]}}}
    return op


ITEM_FILTERS = [
    _q("package", "Package name (case-insensitive)", example="axios"),
    _q("version", "Exact version", example="1.14.1"),
    _q("package_manager", "npm or pip (alias: ecosystem; pypi also accepted)", enum=["npm", "pip"]),
    _q("kind", "Comma-separated kinds", example="malicious,news"),
    _q("source", "Source, e.g. `OSV`, `CISA KEV`, `News: The Hacker News`"),
    _q("severity", "critical, high, medium or low", enum=["critical", "high", "medium", "low"]),
    _q("days", "Dated within the last N days", "integer", example=30),
    _q("published_since", "Dated on or after (YYYY-MM-DD)", example="2026-10-01"),
    _q("limit", "Max rows (default 500, max 10000)", "integer"),
]


def spec():
    s = {
        "openapi": "3.0.3",
        "info": {
            "title": "SSC sources API",
            "version": VERSION,
            "description": (
                "A database of supply-chain security information, built from the scope in `intel_api/config/scope.json` "
                "(packages, vendors, stack, certificate authorities). Background jobs keep it current for that scope, and "
                "feeds only store records about it.\n\n"
                "**Lookups:** an app reads the files it is pointed at and sends the packages (and vendors) it finds to "
                "`POST /v1/lookup`. For each one the API returns what the database has when it is fresh; otherwise it looks it "
                "up from the sources, stores it, and returns it (a package that could not be looked up carries `error`). Package checks, package "
                "pages, searches and vendor records follow the same rule.\n\n"
                "Every source's output is flattened into the **items** table: one row per item x package x version.\n\n"
                "Responses carry only fields with a value (null / empty / false are left out).\n\n"
                "Auth: `Authorization: Bearer <key>` or `X-API-Key: <key>`. Roles: read < write < admin for lookups; "
                "`scan` for laptop scanners (send scans, read their own results) and `agent` for the agents container "
                '(server setting `SSC_INTEL_API_KEYS="read:k1,write:k2,admin:k3,scan:k4,agent:k5"`). With no keys configured '
                "the server listens on 127.0.0.1 only and every local caller is admin."
            ),
        },
        "servers": [
            {
                "url": "http://127.0.0.1:8787",
                "description": "local (python3 -m intel_api serve, Python 3.11+ with the server dependencies)",
            }
        ],
        "security": [{"bearer": []}, {"apiKey": []}],
        "tags": [
            {"name": "Items", "description": "The generic table: every source, structured by package / version"},
            {"name": "Packages", "description": "Package evidence for the gatekeeper, guardrail and pre-commit"},
            {"name": "Lookup", "description": "What an app found in its files: database first, sources on a miss"},
            {"name": "Scope", "description": "What is tracked, and what's new"},
            {
                "name": "Collector",
                "description": "Search results and trust-store data used by the threat-intel collector",
            },
            {"name": "Ingest", "description": "Writes from agents"},
            {
                "name": "Scans",
                "description": "Laptop scanners: send a folder's scope, get back an advisory and action plan",
            },
            {"name": "Agents", "description": "The agents container: take scans waiting for an advisory, return it"},
            {"name": "Service", "description": "Health, sources, jobs, spec"},
        ],
        "paths": {
            "/v1/health": {
                "get": _op(
                    "Service", "Liveness", "Always answers; reports the auth mode.", None, ok=_ok(_ref("Health"))
                )
            },
            "/v1/openapi.json": {
                "get": _op(
                    "Service", "This document", "OpenAPI 3 description of the API.", None, ok=_ok({"type": "object"})
                )
            },
            "/v1/sources": {
                "get": _op(
                    "Service",
                    "Sources, jobs and coverage",
                    "Every source (capabilities, rating, health), every background job (interval, last run, "
                    "errors), search coverage per term type, package-evidence and items table sizes.",
                    "read",
                    ok=_ok(_ref("SourcesStatus")),
                )
            },
            "/v1/items": {
                "get": _op(
                    "Items",
                    "Query the items table",
                    "Rows from every source. Combine filters freely, e.g. everything about one package version, "
                    "every malicious report published this week, or one CVE.",
                    "read",
                    ITEM_FILTERS,
                    ok=_ok(_ref("ItemList")),
                )
            },
            "/v1/news": {
                "get": _op(
                    "Items",
                    "News and social rows",
                    "Same as /v1/items, limited to kind news and social.",
                    "read",
                    ITEM_FILTERS,
                    ok=_ok(_ref("ItemList")),
                )
            },
            "/v1/lookup": {
                "post": _op(
                    "Lookup",
                    "Look up packages and vendors",
                    "Send what an app found in the files it was pointed at. For each package the API returns its stored evidence "
                    "and item rows when they are fresh; otherwise it looks the package up from the sources now, stores it, and "
                    "returns it. A package that could not be looked up carries `error` instead of evidence. Vendors with no "
                    "records are left out of `vendors`. "
                    "Vendors are searched now if they never were. Packages outside the scope are stored too.",
                    "read",
                    body=(
                        _ref("LookupRequest"),
                        {
                            "packages": [
                                {"package_manager": "npm", "name": "axios", "version": "1.13.1"},
                                {"package_manager": "pip", "name": "litellm", "version": "1.107.0"},
                            ],
                            "vendors": ["Railway"],
                        },
                    ),
                    ok=_ok(_ref("LookupResponse")),
                    errors=("400", "401", "403", "413"),
                )
            },
            "/v1/packages/{ecosystem}/{name}": {
                "get": _op(
                    "Lookup",
                    "Everything about one package",
                    "Same as one package of /v1/lookup: stored when fresh, otherwise looked up now, stored and returned. Without "
                    "`version`, the latest version is used.",
                    "read",
                    [
                        _p("ecosystem", "Package manager: npm or pip (pypi)", "npm"),
                        _p("name", "Package name; scoped npm names as @scope/name", "axios"),
                        _q("version", "Exact version", example="1.13.1"),
                    ],
                    ok=_ok(_ref("PackageResult")),
                    errors=("400", "401", "403", "502"),
                )
            },
            "/v1/packages/check": {
                "post": _op(
                    "Packages",
                    "Evidence for packages",
                    "The evidence the gatekeeper's rules need (registry facts, typosquat, OSV/KEV/EPSS/VulnCheck findings, optionally "
                    "social), stored when fresh or looked up now. Registry ages are moved forward to now. Packages that could not be "
                    "looked up are listed in `missing` (clients check those directly). Verdicts are decided by the client.",
                    "read",
                    body=(
                        _ref("CheckRequest"),
                        {
                            "packages": [{"ecosystem": "npm", "name": "axios", "version": "1.13.1"}],
                            "social": False,
                            "resolve_latest": False,
                        },
                    ),
                    ok=_ok(_ref("CheckResponse")),
                    errors=("400", "401", "403", "413"),
                )
            },
            "/v1/search/{kind}": {
                "get": _op(
                    "Collector",
                    "News / social / NVD results for a term",
                    "Stored results for the term; searched now (and stored) if it never was. Only results that name the term are kept.",
                    "read",
                    [
                        _p("kind", "news, social or nvd", "news"),
                        _q("term", "Term (required)", example="Railway"),
                        _q("term_type", "vendor, package, certificate_authority or stack"),
                        _q("days", "Published within the last N days (default 45)", "integer"),
                    ],
                    ok=_ok(_ref("SearchResults")),
                    errors=("400", "401", "403", "502"),
                )
            },
            "/v1/vendors/{name}/signals": {
                "get": _op(
                    "Lookup",
                    "Records about a vendor",
                    "Breach notices, news and social posts that name a vendor; searched now (and stored) if never searched.",
                    "read",
                    [
                        _p("name", "Vendor name", "Railway"),
                        _q("days", "Published within the last N days (default 45)", "integer"),
                    ],
                    ok=_ok(_ref("VendorSignals")),
                )
            },
            "/v1/signals": {
                "get": _op(
                    "Items",
                    "Raw signals",
                    "The raw record per item before flattening (one per advisory/article/post). Prefer /v1/items.",
                    "read",
                    [
                        _q("since", "First seen after (ISO 8601)"),
                        _q("kind", "Comma-separated kinds"),
                        _q("min_reliability", "Minimum rating", "integer"),
                        _q("subject_type", "package, vendor, cve, ca, none"),
                        _q("ecosystem", "PyPI or npm"),
                        _q("name", "Subject name"),
                        _q("source", "Source label"),
                        _q("source_prefix", "Source label prefix, e.g. `News: `"),
                        _q("published_since", "Published on/after"),
                        _q("limit", "Max rows (default 500)", "integer"),
                    ],
                    ok=_ok(_ref("SignalList")),
                )
            },
            "/v1/trust/ca-distrust": {
                "get": _op(
                    "Collector",
                    "Removed root CAs",
                    "Roots that disappeared from Mozilla's trust store.",
                    "read",
                    ok=_ok({"type": "object", "properties": {"signals": {"type": "array", "items": _ref("Signal")}}}),
                )
            },
            "/v1/trust/mozilla-roots": {
                "get": _op(
                    "Collector",
                    "Mozilla trust store",
                    "Current trusted roots as {sha256 fingerprint: label}.",
                    "read",
                    ok=_ok(_ref("MozillaRoots")),
                    errors=("401", "403", "503"),
                )
            },
            "/v1/scope": {
                "get": _op(
                    "Scope",
                    "What is tracked",
                    "The scope: intel_api/config/scope.json (hand-curated; edit the file to change it) plus `discovered`, the "
                    "package versions added automatically when a lookup finds one the database had never seen.",
                    "read",
                    ok=_ok(_ref("ScopeResponse")),
                )
            },
            "/v1/alerts": {
                "get": _op(
                    "Scope",
                    "What's new",
                    "Item rows whose record was first stored after `since` (default: the last 24 hours).",
                    "read",
                    [
                        _q("since", "ISO 8601 (default now - 24 h)"),
                        _q("package", "Package name"),
                        _q("package_manager", "npm or pip", enum=["npm", "pip"]),
                        _q("kind", "Comma-separated kinds"),
                        _q("limit", "Max rows (default 1000)", "integer"),
                    ],
                    ok=_ok(_ref("Alerts")),
                )
            },
            "/v1/signals/breach-notices": {
                "post": _op(
                    "Ingest",
                    "Store breach notices from the threat-intel agent",
                    "The agent's `breach_notices.live.json`. Each is stored under the site it was taken from (e.g. docs.litellm.ai) with "
                    "`data.extracted_by: threat-intel agent`, and its rating is capped at 3, so it can HOLD but never BLOCK.",
                    "write",
                    body=(
                        _ref("BreachNotices"),
                        {
                            "notices": [
                                {
                                    "id": "railway-2026-10",
                                    "type": "platform",
                                    "vendor": "Railway",
                                    "confidence": "high",
                                    "source": "https://blog.railway.com/...",
                                    "published": "2026-10-22",
                                }
                            ]
                        },
                    ),
                    ok=_ok(
                        {
                            "type": "object",
                            "properties": {
                                "received": {"type": "integer"},
                                "stored": {"type": "integer"},
                                "new": {"type": "integer"},
                            },
                        }
                    ),
                )
            },
            "/v1/admin/refresh": {
                "post": _op(
                    "Service",
                    "Run a background job now",
                    "The only call that makes the service contact sources. Without a job name, runs everything due. "
                    "With the scheduler running it runs in the background; with `serve --no-scheduler` it runs before answering.",
                    "admin",
                    body=(_ref("RefreshRequest"), {"job": "news_search"}),
                    ok=_ok(_ref("RefreshResponse")),
                )
            },
            "/v1/register": {
                "post": {
                    **_op(
                        "Scans",
                        "Get a scan key for this computer",
                        "The ssc app and the Claude plugin call this on first use when they have no key, so nobody has to "
                        "hand keys out. Returns a new random key once (only its SHA-256 is stored). It has the `scan` role "
                        "only: send scans, read this key's own results. Limited per address and per day; the server can "
                        "turn it off (`SSC_SELF_REGISTER=0`, then 403).",
                        None,
                        body=({"type": "object", "properties": {"device_name": STR}}, {"device_name": "sam-mbp"}),
                        ok=_ok(
                            {
                                "type": "object",
                                "properties": {"key": STR, "role": {"const": "scan"}, "device": STR},
                                "required": ["key", "role", "device"],
                            }
                        ),
                    ),
                    "responses": {
                        **_ok({"type": "object"}),
                        "403": {"description": "This server hands out no keys"},
                        "429": {"description": "Too many new keys from this address, or today"},
                    },
                }
            },
            "/v1/scans": {
                "post": _op(
                    "Scans",
                    "Send a scan",
                    "What a laptop scanner found in one folder. The server looks every package version and vendor up, "
                    "applies the rules (ALLOW / HOLD / BLOCK), checks fix versions and plans line edits, compares with this "
                    "device's last scan of the folder, and, when something is new, has the agents write an advisory. "
                    "Poll the returned `poll` path. File paths in `found_in` are relative to the scanned folder; `text` is the "
                    "dependency's line, so the plan is made without the files.",
                    "scan",
                    body=(
                        _ref("ScanRequest"),
                        {
                            "folder": "web-app",
                            "device_name": "sam-mbp",
                            "scope": {
                                "packages": [
                                    {
                                        "package_manager": "npm",
                                        "name": "axios",
                                        "versions": ["1.14.1"],
                                        "found_in": [
                                            {
                                                "project": "web-app",
                                                "file": "web-app/package.json",
                                                "line": 7,
                                                "text": '    "axios": "1.14.1"',
                                                "spec": "1.14.1",
                                                "version": "1.14.1",
                                                "version_from": "pinned",
                                            }
                                        ],
                                    }
                                ],
                                "vendors": [{"name": "Railway"}],
                            },
                        },
                    ),
                    ok=_ok(_ref("ScanAccepted")),
                ),
                "get": _op(
                    "Scans",
                    "This device's recent scans",
                    "Newest first. Admin keys see every device's.",
                    "scan",
                    params=[_q("limit", "At most this many (default 20, max 200)", "integer")],
                    ok=_ok(_ref("ScanList")),
                ),
            },
            "/v1/scans/{scan_id}": {
                "get": _op(
                    "Scans",
                    "A scan's status and result",
                    "`status`: queued, assessing, advising (waiting for the agents), agent_running, done or failed. When done: "
                    "`advice` (markdown, from the agents), `plan` (line edits and manual actions), `diff` (the verified edits), "
                    "`findings` (every package not ALLOW) and `changes` (new and resolved since the last scan). `advice_status`: "
                    "written, reused (nothing new: the last advisory), failed, unavailable or pending.",
                    "scan",
                    params=[_p("scan_id", "From POST /v1/scans", "scan_3f2a9c1d8e7b6a50")],
                    ok=_ok(_ref("Scan")),
                    errors=("401", "403", "404"),
                )
            },
            "/v1/scanner-rules": {
                "get": _op(
                    "Scans",
                    "What the scanner detects",
                    "File signatures, package-name and env-var patterns, registry hosts and folders to skip: the rules the laptop "
                    "scanner applies (it ships a copy and uses this one when it can reach the API).",
                    "scan",
                    ok=_ok({"type": "object"}),
                    errors=("401", "403"),
                )
            },
            "/v1/agents/claim": {
                "post": _op(
                    "Agents",
                    "Take the next scan waiting for an advisory",
                    "Returns `job: null` when there is nothing to do. A job not answered within 20 minutes is offered again. "
                    "`files` are what the agents read: assessment, changes since the last scan, the diff, the scan's context.",
                    "agent",
                    ok=_ok(_ref("AgentJob")),
                    errors=("401", "403"),
                )
            },
            "/v1/agents/jobs/{scan_id}/result": {
                "post": _op(
                    "Agents",
                    "Return the advisory for a scan",
                    "`advice`: the markdown advisory; or `error` when the agents could not write one (the scan still finishes "
                    "with its action plan).",
                    "agent",
                    params=[_p("scan_id", "The job's id", "scan_3f2a9c1d8e7b6a50")],
                    body=(_ref("AgentResult"), {"advice": "# Supply-chain advice ...", "cost_usd": 0.48}),
                    ok=_ok(_obj({"ok": BOOL, "id": STR, "advice_status": STR})),
                    errors=("400", "401", "403", "404", "409"),
                )
            },
        },
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer", "description": "API key as a bearer token"},
                "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            },
            "schemas": SCHEMAS,
        },
    }
    return s


STR, INT, NUM, BOOL = {"type": "string"}, {"type": "integer"}, {"type": "number"}, {"type": "boolean"}
NSTR, NINT = {"type": "string", "nullable": True}, {"type": "integer", "nullable": True}


def _obj(props, required=(), desc=None, extra=True):
    o = {"type": "object", "properties": props}
    if required:
        o["required"] = list(required)
    if desc:
        o["description"] = desc
    if extra:
        o["additionalProperties"] = True
    return o


KIND = {"type": "string", "enum": ["malicious", "vuln", "exploited", "breach", "news", "social", "ca_distrust"]}
SCHEMAS = {
    "Error": _obj({"error": STR}, ["error"]),
    "Health": _obj({"ok": BOOL, "version": STR, "time": STR, "auth": STR}),
    "Item": _obj(
        {
            "signal_id": {**STR, "description": "The raw record this row came from (GET /v1/signals)"},
            "kind": KIND,
            "package": {**STR, "example": "axios", "description": "Absent when the item names no package"},
            "version": {**STR, "example": "1.14.1", "description": "One row per version; absent = no version"},
            "package_manager": {"type": "string", "enum": ["npm", "pip"], "example": "npm"},
            "source": {**STR, "example": "OSV"},
            "title": STR,
            "description": {
                **STR,
                "description": "Summary, or the text around the package mention (news/social); fix and CVSS details for advisories",
            },
            "url": STR,
            "date": {
                **STR,
                "example": "2026-03-31",
                "description": "Published date (YYYY-MM-DD), or the date first stored if the source gives none",
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "description": "Absent for news and social",
            },
        },
        ["signal_id", "kind", "source", "title", "url"],
        desc="One row of the generic table: item x package x version. Empty fields are left out.",
    ),
    "ItemList": _obj({"count": INT, "items": {"type": "array", "items": _ref("Item")}}),
    "PackageResult": _obj(
        {
            "package": STR,
            "version": STR,
            "package_manager": {"type": "string", "enum": ["npm", "pip"]},
            "resolved_version": {**STR, "description": "When no version was given: the latest"},
            "collected_at": STR,
            "error": STR,
            "evidence": _ref("Evidence"),
            "items": {
                "type": "array",
                "items": _ref("Item"),
                "description": "Rows for this version plus rows without a version",
            },
        },
        ["package", "package_manager"],
    ),
    "VendorSignals": _obj(
        {"vendor": STR, "days": INT, "count": INT, "signals": {"type": "array", "items": _ref("Signal")}}
    ),
    "LookupRequest": _obj(
        {
            "packages": {
                "type": "array",
                "maxItems": 2000,
                "items": _obj(
                    {"package_manager": {"type": "string", "enum": ["npm", "pip"]}, "name": STR, "version": STR},
                    ["package_manager", "name"],
                ),
            },
            "vendors": {"type": "array", "maxItems": 50, "items": STR},
            "social": {**BOOL, "description": "Include social posts in the evidence"},
            "resolve_latest": {**BOOL, "description": "No version = latest"},
            "max_age_hours": {**NUM, "description": "Older stored data is looked up again (default 24)"},
            "days": {**INT, "description": "Vendor records from the last N days (default 45)"},
        }
    ),
    "LookupResponse": _obj(
        {
            "looked_up_at": STR,
            "packages": {"type": "array", "items": _ref("PackageResult")},
            "vendors": {"type": "array", "items": _ref("VendorSignals")},
        }
    ),
    "ScopeResponse": _obj(
        {
            "file": STR,
            "packages": INT,
            "package_versions": INT,
            "vendors": INT,
            "stack": INT,
            "certificate_authorities": INT,
            "discovered_package_versions": INT,
            "scope": {"type": "object"},
            "discovered": {
                "type": "array",
                "description": "Package versions added from lookups, oldest first: {package_manager, name, version}",
                "items": {"type": "object"},
            },
        }
    ),
    "Signal": _obj(
        {
            "id": STR,
            "kind": KIND,
            "subject": _obj({"type": STR, "ecosystem": STR, "name": STR}, desc="Absent when the record names nothing"),
            "title": STR,
            "url": STR,
            "published_at": STR,
            "first_seen_at": STR,
            "source": STR,
            "reliability": INT,
            "may_block": BOOL,
            "data": {"type": "object", "description": "Only keys with a value"},
        },
        ["id", "kind", "title", "url", "source", "may_block"],
        desc="Raw record, one per advisory / article / post. Empty fields are left out.",
    ),
    "SignalList": _obj({"count": INT, "signals": {"type": "array", "items": _ref("Signal")}}),
    "Package": _obj(
        {
            "ecosystem": {"type": "string", "enum": ["PyPI", "npm", "pypi"]},
            "name": STR,
            "version": {**NSTR, "description": "Omit/null for unpinned"},
        },
        ["ecosystem", "name"],
    ),
    "CheckRequest": _obj(
        {
            "packages": {"type": "array", "items": _ref("Package"), "maxItems": 2000},
            "social": {**BOOL, "description": "Include stored social posts"},
            "resolve_latest": {**BOOL, "description": "No version = newest (what an installer would pick)"},
        },
        ["packages"],
    ),
    "Finding": _obj(
        {
            "id": STR,
            "source": STR,
            "malicious": BOOL,
            "in_kev": BOOL,
            "summary": STR,
            "severity": STR,
            "cves": {"type": "array", "items": STR},
            "fixed_in": {"type": "array", "items": STR},
            "symbols": {
                "type": "array",
                "items": STR,
                "description": "Functions and APIs the advisory names (e.g. yaml.load, zipObjectDeep): the Claude plugin "
                "looks for them in the project's code",
            },
            "malicious_other_version": BOOL,
            "in_vulncheck_kev": BOOL,
            "epss_max": NUM,
            "versions": {"type": "array", "items": STR},
            "url": STR,
            "published": STR,
        },
        ["id", "source", "malicious", "in_kev"],
        desc="Same meaning as the gatekeeper's own evidence; optional fields only when they have a value",
    ),
    "Evidence": _obj(
        {
            "registry": _obj(
                {
                    "exists": BOOL,
                    "unverified": STR,
                    "latest": STR,
                    "release_count": INT,
                    "first_release_days": NUM,
                    "version_exists": BOOL,
                    "version_yanked": BOOL,
                    "version_age_days": NUM,
                    "install_scripts": {"type": "object"},
                    "deprecated": STR,
                },
                ["exists"],
                desc="Facts the rules read",
            ),
            "typosquat_of": {"type": "array", "items": STR},
            "vulns": {"type": "array", "items": _ref("Finding")},
            "social": {
                "type": "array",
                "items": _obj(
                    {"source": STR, "title": STR, "url": STR, "date": STR, "engagement": INT, "other_version": BOOL}
                ),
                "description": "Only when social was requested and the package has been searched",
            },
            "social_checked": BOOL,
        },
        ["registry", "typosquat_of", "vulns"],
    ),
    "CheckResult": _obj(
        {
            "ecosystem": STR,
            "name": STR,
            "version": STR,
            "resolved_version": {**STR, "description": "Only when the API picked the version (resolve_latest)"},
            "collected_at": STR,
            "evidence": _ref("Evidence"),
        },
        ["ecosystem", "name", "collected_at", "evidence"],
    ),
    "CheckResponse": _obj(
        {
            "read_at": STR,
            "results": {"type": "array", "items": _ref("CheckResult")},
            "missing": {
                "type": "array",
                "items": _ref("Package"),
                "description": "Could not be looked up (with `error`): check these directly",
            },
        }
    ),
    "SearchResults": _obj(
        {
            "kind": STR,
            "term": STR,
            "covered": BOOL,
            "searched_at": STR,
            "query": STR,
            "items": {"type": "array", "items": _ref("Signal")},
        }
    ),
    "MozillaRoots": _obj({"as_of": STR, "count": INT, "roots": {"type": "object", "additionalProperties": STR}}),
    "Alerts": _obj(
        {
            "since": STR,
            "count": INT,
            "items": {
                "type": "array",
                "items": {
                    "allOf": [
                        _ref("Item"),
                        _obj({"first_seen_at": {**STR, "description": "When the record was first stored"}}),
                    ]
                },
            },
        }
    ),
    "BreachNotices": _obj(
        {
            "notices": {
                "type": "array",
                "items": _obj(
                    {
                        "id": STR,
                        "type": {"type": "string", "enum": ["platform", "developer_tool", "package"]},
                        "vendor": STR,
                        "package": STR,
                        "ecosystem": STR,
                        "versions": {"type": "array", "items": STR},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        "source": STR,
                        "published": STR,
                    }
                ),
            }
        },
        ["notices"],
    ),
    "RefreshRequest": _obj(
        {
            "job": {
                **STR,
                "description": "Job key (see /v1/sources jobs); omit for everything due",
                "enum": [
                    "osv",
                    "cisa_kev",
                    "oss_security",
                    "news_rss",
                    "mozilla_ca_store",
                    "news_search",
                    "social_search",
                    "nvd_search",
                    "package_evidence",
                    "articles",
                    "index",
                    "maintenance",
                ],
            }
        }
    ),
    "RefreshResponse": _obj(
        {
            "accepted": BOOL,
            "job": STR,
            "mode": {"type": "string", "enum": ["background", "ran now"]},
            "result": {"type": "object"},
        }
    ),
    "ScanRequest": _obj(
        {
            "folder": {**STR, "description": "The scanned folder's name"},
            "device_name": {**STR, "description": "Shown in results; the device itself is identified by its key"},
            "scope": _obj(
                {
                    "packages": {
                        "type": "array",
                        "items": _obj(
                            {
                                "package_manager": {"type": "string", "enum": ["npm", "pip"]},
                                "name": STR,
                                "versions": {"type": "array", "items": STR, "description": "Empty: the latest version"},
                                "found_in": {
                                    "type": "array",
                                    "items": _obj(
                                        {
                                            "project": STR,
                                            "file": STR,
                                            "line": INT,
                                            "text": STR,
                                            "spec": STR,
                                            "version": NSTR,
                                            "version_from": {
                                                "type": "string",
                                                "enum": ["pinned", "range", "lockfile", "unpinned (latest)"],
                                            },
                                        }
                                    ),
                                },
                            },
                            ["package_manager", "name"],
                        ),
                    },
                    "vendors": {
                        "type": "array",
                        "items": _obj({"name": STR, "aliases": {"type": "array", "items": STR}}),
                    },
                    "stack": {"type": "array", "items": STR},
                    "certificate_authorities": {"type": "array", "items": STR},
                    "internal_packages": {"type": "array", "items": STR},
                    "projects": {"type": "array", "items": {"type": "object"}},
                }
            ),
        },
        ["folder", "scope"],
    ),
    "ScanAccepted": _obj({"id": STR, "status": STR, "poll": STR}),
    "ScanList": _obj(
        {
            "scans": {
                "type": "array",
                "items": _obj(
                    {
                        "id": STR,
                        "device_name": NSTR,
                        "folder": STR,
                        "status": STR,
                        "advice_status": NSTR,
                        "created_at": STR,
                        "updated_at": STR,
                    }
                ),
            }
        }
    ),
    "Scan": _obj(
        {
            "id": STR,
            "status": STR,
            "folder": STR,
            "device_name": NSTR,
            "created_at": STR,
            "updated_at": STR,
            "advice_status": NSTR,
            "summary": _obj({"BLOCK": INT, "HOLD": INT, "ALLOW": INT, "UNKNOWN": INT}),
            "changes": _obj(
                {
                    "first_scan": BOOL,
                    "new": {"type": "array", "items": STR},
                    "resolved": {"type": "array", "items": STR},
                    "previous_scan": NSTR,
                }
            ),
            "projects": {
                "type": "array",
                "description": "Counts per project in the scanned folder",
                "items": _obj({"project": STR, "BLOCK": INT, "HOLD": INT, "ALLOW": INT, "UNKNOWN": INT}),
            },
            "actions": {
                "type": "array",
                "description": "Every action item, one row each: key (stable, for ticking off), priority (block/hold), "
                "kind (package/secret/certificate/other), project, item, problem, where, action, edits (indexes into "
                "plan.edits that carry it out), sources",
                "items": {"type": "object"},
            },
            "advice_summary": {**NSTR, "description": "The advisory's Summary section"},
            "advice": {**NSTR, "description": "Markdown advisory from the agents: Summary and Other actions"},
            "plan": _obj(
                {
                    "edits": {"type": "array", "items": {"type": "object"}},
                    "manual": {"type": "array", "items": {"type": "object"}},
                }
            ),
            "diff": STR,
            "findings": {"type": "array", "items": {"type": "object"}},
            "vendors": {"type": "array", "items": {"type": "object"}},
            "error": STR,
        }
    ),
    "AgentJob": _obj(
        {
            "job": {
                "nullable": True,
                **_obj({"id": STR, "folder": STR, "files": {"type": "object", "additionalProperties": STR}}),
            }
        }
    ),
    "AgentResult": _obj({"advice": STR, "error": STR, "cost_usd": NUM}),
    "SourcesStatus": _obj(
        {
            "policy": {"type": "object"},
            "sources": {"type": "object", "additionalProperties": {"type": "object"}},
            "jobs": {
                "type": "object",
                "additionalProperties": _obj(
                    {"enabled": BOOL, "every_seconds": INT, "last_run_at": NSTR, "last_ok_at": NSTR, "last_error": NSTR}
                ),
            },
            "search_coverage": {"type": "array", "items": {"type": "object"}},
            "package_evidence": _obj({"stored": INT, "oldest": NSTR}),
            "items": {"type": "object"},
            "store": {"type": "object"},
        }
    ),
}
