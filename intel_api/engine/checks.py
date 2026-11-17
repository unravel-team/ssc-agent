"""Consistency checks on a finished scan: the rules an advisory must never break, whatever the wording.

The agents refer to what they write about by id (engine/advice.py): each summary point names the action items it is
about, each row they add names its evidence. So every check is exact: an id exists, an item is open, a project is
one of the scan's, a source is one the server gave. Nothing here matches names or wording.

check() is pure; report() runs it on a stored scan and logs what it finds. They run on every scan as it finishes,
the problems are returned with the scan as `checks`, and `python3 -m intel_api checks` shows how often each rule
failed over recent scans (and how often the agents fixed a problem when asked to).
"""

from . import actions

RULES = {
    "fields": "every action item has a known priority, criticality and kind, an action, and (for packages, secrets "
    "and lockfiles) a place in the project; no two items share a key",
    "summary_row": "every point of the Summary refers to at least one open action item, and only to items that exist",
    "summary_done": "no point of the Summary refers to an item the developer already ticked off",
    "fix_verified": "every automatic edit is verified and moves to the version the rules checked",
    "other_project": "every row the agents add names exactly one project of the scan",
    "other_source": "every row the agents add cites evidence the server gave them (by its id in evidence.json)",
    "structured": "the advisory refers to items and evidence by id (one written as free text can't be checked)",
    "supported": "what each summary point and agent row says is backed by the items and evidence it refers to "
    "(judged by a separate AI check in the agents container)",
}
KINDS = set(actions.KIND)


def _problem(rule, detail):
    return {"rule": rule, "detail": str(detail)[:300]}


def _fields(rows):
    """fields: every item well formed, no two with the same key."""
    out, seen = [], set()
    for r in rows:
        label = f"{r.get('project')}/{r.get('item')}"
        if r.get("key") in seen:
            out.append(_problem("fields", f"two items share the key {r.get('key')}"))
        seen.add(r.get("key"))
        if r.get("priority") not in actions.PRIORITY:
            out.append(_problem("fields", f"{label}: unknown priority {r.get('priority')!r}"))
        if r.get("criticality") not in actions.LEVELS:
            out.append(_problem("fields", f"{label}: unknown criticality {r.get('criticality')!r}"))
        if r.get("kind") not in KINDS:
            out.append(_problem("fields", f"{label}: unknown kind {r.get('kind')!r}"))
        if not (isinstance(r.get("action"), str) and r["action"].strip()):
            out.append(_problem("fields", f"{label}: no action"))
        if r.get("kind") in ("package", "secret", "lockfile") and not r.get("where"):
            out.append(_problem("fields", f"{label}: no place in the project"))
    return out


def _fixes(rows, plan, findings):
    """fix_verified: every automatic edit is in the plan, verified, and moves to the version the rules checked."""
    by_version = {(p.get("package_manager"), p.get("package"), p.get("version")): p for p in findings}
    out = []
    for r in (r for r in rows if r.get("kind") == "package"):
        for i in r.get("edits") or []:
            e = plan[i] if isinstance(i, int) and 0 <= i < len(plan) else None
            if e is None:
                out.append(_problem("fix_verified", f"{r.get('item')}: edit {i} is not in the plan"))
                continue
            fix = (by_version.get((e.get("package_manager"), e.get("package"), e.get("from"))) or {}).get("fix") or {}
            if not e.get("verified"):
                out.append(_problem("fix_verified", f"{r.get('item')}: automatic edit to {e.get('to')} is unverified"))
            elif fix.get("to") and e.get("to") != fix.get("to") and e.get("change") != "replace":
                out.append(
                    _problem("fix_verified", f"{r.get('item')}: edit moves to {e.get('to')}, rules checked {fix['to']}")
                )
    return out


def _advice(result, rows, done):
    """The agents' part: what the server left out when it accepted the advisory, and the accepted advice against the
    items as they are now (a reused advisory may refer to items that are gone or ticked off since)."""
    data = result.get("advice_data")
    if not data:
        has_text = bool(result.get("advice"))
        return [_problem("structured", "the advisory has no references, so it can't be checked")] if has_text else []
    dropped = (result.get("advice_problems") or {}).get("dropped") or []
    out = [_problem(p["rule"], f"left out: {p['detail']}") for p in dropped]
    keys = {r.get("key") for r in rows}
    for p in data.get("summary") or []:
        text = repr(str(p.get("text") or "")[:80])
        gone = [k for k in p.get("items") or [] if k not in keys]
        ticked = [k for k in p.get("items") or [] if k in done]
        if gone:
            out.append(_problem("summary_row", f"{text} refers to items no longer listed: {', '.join(gone)}"))
        if ticked:
            out.append(_problem("summary_done", f"{text} refers to done items: {', '.join(ticked)}"))
    projects = {p.get("project") for p in result.get("projects") or []}
    for r in data.get("other_actions") or []:
        if projects and r.get("project") not in projects:
            out.append(_problem("other_project", f"{r.get('item')}: {r.get('project')!r} is not a project of the scan"))
        if not r.get("sources"):
            out.append(_problem("other_source", f"{r.get('item')}: cites no evidence"))
    return out


def check(result, done_keys=()):
    """Problems in a scan result (the shape scans.view returns), as [{rule, detail}]. done_keys: the items the
    developer had closed when the scan was sent."""
    rows = result.get("actions") or []
    plan = (result.get("plan") or {}).get("edits") or []
    return _fields(rows) + _fixes(rows, plan, result.get("findings") or []) + _advice(result, rows, set(done_keys))


def report(store, scan_id, log=None):
    """Check a stored scan and log its problems. -> the problems. Never raises: a check must not break a scan."""
    from . import scans

    try:
        scan = store.get_scan(scan_id)
        if not scan or not scan.get("result"):
            return []
        problems = scans.view(scan).get("checks") or []
    except Exception as e:  # noqa: BLE001 - logged; the scan itself is fine
        problems = [_problem("fields", f"the checks could not run: {type(e).__name__}: {e}")]
    if problems and log:
        log(
            f"checks: scan {scan_id}: {len(problems)} problem(s): "
            + " | ".join(f"{p['rule']}: {p['detail']}" for p in problems)[:2000]
        )
    return problems


def summarize(store, limit=200):
    """How often each rule failed over the newest `limit` finished scans, and how the agents did on first try."""
    from . import scans

    checked, failed, retried = 0, 0, 0
    by_rule, first_try, skipped = dict.fromkeys(RULES, 0), dict.fromkeys(RULES, 0), {}
    examples = {}
    for s in store.list_scans(None, limit=limit):
        if s.get("status") != "done":
            continue
        scan = store.get_scan(s["id"])
        problems = scans.view(scan).get("checks") or []
        tries = ((scan.get("result") or {}).get("advice_problems") or {}).get("tries") or []
        checked += 1
        failed += bool(problems)
        retried += len(tries) > 1
        for p in problems:
            by_rule[p["rule"]] = by_rule.get(p["rule"], 0) + 1
            examples.setdefault(p["rule"], f"{s['id']}: {p['detail']}")
        for p in tries[0] if tries else []:
            first_try[p["rule"]] = first_try.get(p["rule"], 0) + 1
        for d in (scan.get("scope") or {}).get("done_actions") or []:
            if isinstance(d, dict) and d.get("state") == "skipped":  # the developer's word: not relevant to them
                kind = d.get("kind") or "unknown"
                skipped.setdefault(kind, {})[d.get("item") or d.get("key")] = d.get("why") or ""
    return {
        "scans_checked": checked,
        "scans_with_problems": failed,
        "problems_by_rule": by_rule,
        "agents_asked_to_correct": retried,
        "first_try_problems_by_rule": first_try,
        # relevance, as the developers judge it: items they skipped as not relevant, by kind, with their reasons
        "skipped_items_by_kind": {
            k: {"count": len(v), "examples": dict(list(v.items())[:5])} for k, v in skipped.items()
        },
        "examples": examples,
    }
