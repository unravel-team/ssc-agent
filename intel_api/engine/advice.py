"""Structured advice: the agents refer to things by id instead of describing them, so the server can check every
claim exactly (no matching of names or wording).

The agents get two numbered lists with each job (agent_files):
  items.json      the action items the rules built: I1, I2, ... (with whether the developer ticked each off)
  evidence.json   every source the server has for this scan: E1, E2, ... (advisories, malware records, news,
                  vendor reports, certificate reports, registry pages, docs)
and write advice.json:
  {"urgency": "High",
   "summary": [{"text": "Upgrade lodash in web to 4.18.1: prototype pollution", "refs": ["I3"]},
               {"text": "Rotate the secrets stored in Railway: confirmed breach", "refs": ["R1"]}],
   "other_actions": [{"id": "R1", "project": "api", "item": "Railway (vendor)", "criticality": "High",
                      "action": "Rotate the secrets stored in Railway", "evidence": ["E7"]}]}

validate() checks it against the lists and returns the resolved advice (ids replaced by item keys and source links)
plus the problems it found, each under the name of the rule it breaks (engine/checks.py). render() writes the
markdown advisory the app and the plugin show. Both lists are rebuilt from the stored assessment, so they are
always the same for a scan.
"""

import json
import re

from . import actions

LEVELS = actions.LEVELS
MAX_POINTS, MAX_ROWS, MAX_TEXT = 3, 5, 300
ITEM_ID, ROW_ID, EVIDENCE_ID = re.compile(r"^I\d+$"), re.compile(r"^R\d+$"), re.compile(r"^E\d+$")


# ---------------------------------------------------------------- what the agents get
def items(assessment, done_keys=()):
    """The rules' action items, numbered: [{id, key, project, item, kind, criticality, priority, problem, action,
    where, done}]."""
    done = set(done_keys)
    return [
        {
            "id": f"I{i}",
            **{
                k: r[k]
                for k in ("key", "project", "item", "kind", "criticality", "priority", "problem", "action", "where")
            },
            "done": r["key"] in done,
        }
        for i, r in enumerate(actions.build(assessment), 1)
    ]


def evidence(assessment):
    """Every source the server has for this scan, numbered: [{id, about, title, url}] (one entry per link)."""
    out, seen = [], set()

    def add(about, title, url):
        if isinstance(url, str) and url.startswith("http") and url not in seen:
            seen.add(url)
            out.append({"id": f"E{len(out) + 1}", "about": about, "title": str(title or "")[:200], "url": url})

    for pkg in assessment.get("packages") or []:
        if pkg.get("verdict") in ("BLOCK", "HOLD"):
            about = f"{pkg.get('package')} {pkg.get('version') or ''}".strip()
            severity = {actions.osv(a["id"]): a.get("severity") for a in pkg.get("advisories") or [] if a.get("id")}
            for s in actions._sources(pkg):
                title = s.get("title") or s.get("text")
                if severity.get(s.get("url")):  # an advisory: its id and severity belong to the fact
                    title = f"{s.get('text')} ({severity[s['url']]} severity): {title}"
                add(about, title, s.get("url"))
    for v in assessment.get("vendors") or []:
        for r in v.get("records") or []:
            add(f"{v.get('vendor')} (vendor)", r.get("title"), r.get("url"))
    for c in assessment.get("certificates") or []:
        for r in c.get("evidence") or []:
            add(f"{c.get('ca')} (certificate authority)", r.get("title"), r.get("url"))
    for r in actions.build(assessment):  # docs the rules cite (lockfiles)
        for s in r.get("sources") or []:
            add(r["item"], s.get("title") or s.get("text"), s.get("url"))
    return out


def agent_files(assessment, done_keys=()):
    return {
        "items.json": json.dumps(items(assessment, done_keys), indent=2),
        "evidence.json": json.dumps(evidence(assessment), indent=2),
    }


# ---------------------------------------------------------------- checking what they wrote
def _problem(rule, detail):
    return {"rule": rule, "detail": str(detail)[:300]}


def _text(v, limit=MAX_TEXT):
    return v.strip()[:limit] if isinstance(v, str) else ""


def _entries(data, field, limit, problems):
    """A list field of advice.json, cut to `limit` entries (each cut or malformed one is a problem)."""
    raw = data.get(field) or []
    if not isinstance(raw, list):
        problems.append(_problem("fields", f"{field} must be a list"))
        return []
    if len(raw) > limit:
        problems.append(_problem("fields", f"at most {limit} entries in {field}; the rest were left out"))
    return raw[:limit]


def _row(n, r, projects, ev, unbacked):
    """One of the agents' own rows. -> (its id, the resolved row or None when it breaks a rule, problems)."""
    if not isinstance(r, dict):
        return f"R{n}", None, [_problem("fields", f"other action {n} is not an object")]
    rid = r["id"] if isinstance(r.get("id"), str) and ROW_ID.match(r["id"]) else f"R{n}"
    label = f"{rid} {_text(r.get('item'), 80)!r}"
    item, action, project = _text(r.get("item"), 120), _text(r.get("action")), r.get("project")
    refs = r.get("evidence") if isinstance(r.get("evidence"), list) else []
    sources = [ev[e] for e in refs if e in ev]
    unknown = [str(e) for e in refs if e not in ev]
    problems, fatal = [], []
    if unknown:  # reported, but the row stands on the evidence that was given
        problems.append(_problem("other_source", f"{label}: no evidence {', '.join(unknown)} was given"))
    if not item or not action:
        fatal.append(_problem("fields", f"{label}: needs an item and an action"))
    if r.get("criticality") not in LEVELS:
        fatal.append(_problem("fields", f"{label}: criticality must be one of {', '.join(LEVELS)}"))
    if project not in projects:
        fatal.append(_problem("other_project", f"{label}: {project!r} is not one project of this scan"))
    if not sources:
        fatal.append(_problem("other_source", f"{label}: cites no evidence from evidence.json"))
    if rid in unbacked:
        fatal.append(_problem("supported", f"{label}: the evidence doesn't back it: {unbacked[rid]}"))
    if fatal:
        return rid, None, problems + fatal
    resolved = {
        "key": actions.other_key(project, item),
        "project": project,
        "item": item,
        "criticality": r["criticality"],
        "action": action,
        "sources": [
            {"url": s["url"], "text": s["title"] or actions.host(s["url"]), "title": s["about"]} for s in sources
        ],
    }
    return rid, resolved, problems


def _point(n, p, its, row_keys, unbacked, anything_open):
    """One summary point. -> (the resolved point or None when it breaks a rule, problems)."""
    text = _text(p.get("text")) if isinstance(p, dict) else ""
    refs = p.get("refs") if isinstance(p, dict) and isinstance(p.get("refs"), list) else []
    label = f"point {n} {text[:60]!r}"
    if not text:
        return None, [_problem("fields", f"summary point {n} has no text")]
    if f"P{n}" in unbacked:
        return None, [_problem("supported", f"{label}: its items don't back it: {unbacked[f'P{n}']}")]
    done = [r for r in refs if r in its and its[r]["done"]]
    unknown = [str(r) for r in refs if r not in its and r not in row_keys]
    problems = []
    if done:
        problems.append(_problem("summary_done", f"{label}: is about {', '.join(done)}, already done"))
    if unknown:
        problems.append(_problem("summary_row", f"{label}: refers to {', '.join(unknown)}, which is not an open item"))
    if problems:
        return None, problems
    keys = [its[r]["key"] for r in refs if r in its] + [row_keys[r] for r in refs if r in row_keys]
    if not keys and anything_open:  # only "nothing is left" may refer to nothing
        return None, [_problem("summary_row", f"{label}: refers to no item")]
    return {"text": text, "items": keys}, []


def validate(data, assessment, projects, done_keys=(), unsupported=()):
    """-> (resolved advice, problems). Anything that breaks a rule is left out of the resolved advice and reported.
    projects: the project names of the scan. unsupported: [{claim, why}] from the support check (agents/runner.py):
    summary points (P1, P2, ...) and rows (R1, ...) whose facts don't back what they say; they are left out too."""
    if not isinstance(data, dict):
        return None, [_problem("fields", "advice.json is not a JSON object")]
    if "invalid_json" in data:  # the runner could not parse the file (agents/runner.py)
        return None, [_problem("fields", f"advice.json is not valid JSON: {data['invalid_json']}")]
    unbacked = {u.get("claim"): str(u.get("why") or "")[:200] for u in unsupported or [] if isinstance(u, dict)}
    its = {i["id"]: i for i in items(assessment, done_keys)}
    ev = {e["id"]: e for e in evidence(assessment)}
    problems = []

    urgency = data.get("urgency")
    if urgency not in LEVELS:
        problems.append(_problem("fields", f"urgency must be one of {', '.join(LEVELS)}, not {urgency!r}"))
        urgency = None

    rows, row_keys = [], {}
    for n, r in enumerate(_entries(data, "other_actions", MAX_ROWS, problems), 1):
        rid, row, found = _row(n, r, set(projects), ev, unbacked)
        problems += found
        if row:
            rows.append(row)
            row_keys[rid] = row["key"]

    open_items = [i for i in its.values() if not i["done"]]
    anything_open = bool(open_items or rows)
    points = []
    for n, p in enumerate(_entries(data, "summary", MAX_POINTS, problems), 1):
        point, found = _point(n, p, its, row_keys, unbacked, anything_open)
        problems += found
        if point:
            points.append(point)
    if not points and anything_open:
        problems.append(_problem("summary_row", "no valid summary point"))
    if urgency is None:
        urgency = min((i["criticality"] for i in open_items), key=actions.RANK.get, default="Low")
    # open: whether anything is left to do, so an empty summary never claims there is nothing (render)
    return {"urgency": urgency, "summary": points, "other_actions": rows, "open": anything_open}, problems


# ---------------------------------------------------------------- the advisory as people read it
def _cell(v):
    return str(v or "").replace("|", "/").replace("\n", " ")


def render(resolved):
    """The markdown advisory (Summary, then Other actions) from resolved advice."""
    out = ["## Summary", "", f"**{resolved['urgency']}**"]
    # every point was left out (or none was written): never say "nothing left" above open items
    fallback = "- See the action items below." if resolved.get("open", True) else "- Nothing urgent is left."
    out += [f"- {p['text']}" for p in resolved["summary"]] or [fallback]
    if resolved["other_actions"]:
        out += [
            "",
            "## Other actions",
            "",
            "| Project | Item | Criticality | Action | Source |",
            "|---|---|---|---|---|",
        ]
        for r in resolved["other_actions"]:
            src = r["sources"][0]
            link = f"[{_cell(src['text'])[:80]}]({src['url']})"
            out.append(
                f"| {_cell(r['project'])} | {_cell(r['item'])} | {r['criticality']} | {_cell(r['action'])} | {link} |"
            )
    return "\n".join(out) + "\n"
