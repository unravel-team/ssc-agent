//! Ticks on action items, kept per folder in `~/.ssc/results/<folder>/done.json`:
//!
//! ```json
//! {"<action key>": {"how": "ticked" | "applied" | "resolved", "at": "<ISO time>", "row": {project, item, ...}}}
//! ```
//!
//! - `ticked`: the developer marked it done (in the app, or through the Claude plugin);
//! - `applied`: the Claude plugin applied its edits;
//! - `resolved`: a later scan no longer found it;
//! - `skipped`: the developer marked it not relevant to them, or won't do it (`why`: their reason, if given).
//!
//! So an item is pending (no record), done (ticked, applied or resolved) or skipped. The state and reason go to the
//! server with each scan, so the advisory stops raising a closed item, and skips show which items aren't relevant.
//!
//! Keys come from the server's `actions` and stay the same while the problem does, so a tick survives rescans.
//! A `resolved` or `applied` item that a later scan still finds is unticked (the fix was undone or didn't take); a
//! manual tick stays (rotating a secret doesn't take it out of the file, so the scan keeps seeing it).

use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::{app, util};

pub fn path(label: &str) -> PathBuf {
    app::folder_results(label).join("done.json")
}

pub fn load(label: &str) -> Map<String, Value> {
    load_at(&path(label))
}

fn load_at(p: &Path) -> Map<String, Value> {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn save_at(p: &Path, done: &Map<String, Value>) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    app::save_json(p, &Value::Object(done.clone()))
}

/// What is kept of an action row so a done item can still be shown after it left the scan.
fn snapshot(row: &Value) -> Value {
    json!({"project": row["project"], "item": row["item"], "problem": row["problem"], "action": row["action"],
           "where": row["where"], "priority": row["priority"], "criticality": row["criticality"], "kind": row["kind"],
           "sources": row["sources"]})
}

/// An item's state from its record: "pending" (none), "skipped", or "done".
pub fn state_of(record: Option<&Value>) -> &'static str {
    match record {
        None => "pending",
        Some(r) if r["how"] == "skipped" => "skipped",
        Some(_) => "done",
    }
}

/// Set one item's state: "done" (the developer did it), "skipped" (with their reason, if any) or "pending".
pub fn set_state(label: &str, key: &str, state: &str, why: &str, row: &Value) -> Result<(), String> {
    set_state_at(&path(label), key, state, why, row)
}

fn set_state_at(p: &Path, key: &str, state: &str, why: &str, row: &Value) -> Result<(), String> {
    let mut all = load_at(p);
    match state {
        "pending" => {
            all.remove(key);
        }
        "done" | "skipped" => {
            let mut rec = json!({"how": if state == "done" { "ticked" } else { "skipped" }, "at": util::now_iso(),
                                 "row": snapshot(row)});
            let why: String = why.trim().chars().take(200).collect();
            if state == "skipped" && !why.is_empty() {
                rec["why"] = json!(why);
            }
            all.insert(key.to_string(), rec);
        }
        other => return Err(format!("unknown state {other:?}: done, skipped or pending")),
    }
    save_at(p, &all)
}

fn keys(actions: &Value) -> HashSet<String> {
    actions
        .as_array()
        .map(|a| a.iter().filter_map(|r| r["key"].as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// After a scan: tick what the previous scan listed and this one no longer finds (rule-based rows only); untick `resolved` and `applied`
/// items it still finds. -> how many were newly ticked.
pub fn after_scan(label: &str, previous: &Value, current: &Value) -> Result<usize, String> {
    after_scan_at(&path(label), previous, current)
}

fn after_scan_at(p: &Path, previous: &Value, current: &Value) -> Result<usize, String> {
    let now = keys(current);
    let mut all = load_at(p);
    let mut changed = 0;
    for row in previous.as_array().into_iter().flatten() {
        let Some(k) = row["key"].as_str() else { continue };
        // the agent's own rows ("other") are written fresh by AI each time: one missing is no proof of a fix
        if row["kind"] == "other" {
            continue;
        }
        if !now.contains(k) && !all.contains_key(k) {
            all.insert(
                k.to_string(),
                json!({"how": "resolved", "at": util::now_iso(), "row": snapshot(row)}),
            );
            changed += 1;
        }
    }
    let back: Vec<String> = all
        .iter()
        .filter(|(k, v)| (v["how"] == "resolved" || v["how"] == "applied") && now.contains(*k))
        .map(|(k, _)| k.clone())
        .collect();
    for k in &back {
        all.remove(k);
    }
    if changed > 0 || !back.is_empty() {
        save_at(p, &all)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn row(key: &str) -> Value {
        json!({"key": key, "project": "p", "item": key, "action": "do it", "where": ["f:1"], "priority": "block",
               "kind": "package"})
    }

    #[test]
    fn ticks_resolve_and_come_back() {
        let t = TempDir::new();
        let p = t.path().join("done.json");
        set_state_at(&p, "a", "done", "", &row("a")).unwrap();
        assert_eq!(load_at(&p)["a"]["how"], "ticked");
        assert_eq!(load_at(&p)["a"]["row"]["action"], "do it");

        // b and c were listed; c is gone now: c is resolved, a keeps its manual tick
        let mut ai = row("x");
        ai["kind"] = json!("other");
        let prev = json!([row("a"), row("b"), row("c"), ai]);
        let now = json!([row("a"), row("b")]);
        assert_eq!(after_scan_at(&p, &prev, &now).unwrap(), 1);
        let d = load_at(&p);
        assert_eq!(
            (d["a"]["how"].as_str(), d["c"]["how"].as_str()),
            (Some("ticked"), Some("resolved"))
        );
        assert!(!d.contains_key("b"));
        assert!(!d.contains_key("x")); // an agent row that disappeared is not "fixed"

        // c comes back in a later scan: unticked again; a manual tick stays even while a is still listed
        assert_eq!(
            after_scan_at(&p, &now, &json!([row("a"), row("b"), row("c")])).unwrap(),
            0
        );
        let d = load_at(&p);
        assert!(!d.contains_key("c"));
        assert!(d.contains_key("a"));

        // an applied fix that a later scan still finds (undone, or it didn't take) is unticked
        let mut all = load_at(&p); // the Claude plugin records an applied fix this way
        all.insert("b".into(), json!({"how": "applied", "at": "x", "row": row("b")}));
        save_at(&p, &all).unwrap();
        after_scan_at(&p, &now, &now).unwrap();
        assert!(!load_at(&p).contains_key("b"));

        set_state_at(&p, "a", "pending", "", &row("a")).unwrap();
        assert!(load_at(&p).is_empty());

        // skipped with a reason: kept through rescans that still find it, like a manual tick
        set_state_at(&p, "c", "skipped", "  we don't use Docker Hub ", &row("c")).unwrap();
        assert_eq!((load_at(&p)["c"]["how"].as_str(), load_at(&p)["c"]["why"].as_str()), (Some("skipped"), Some("we don't use Docker Hub")));
        assert_eq!(state_of(load_at(&p).get("c")), "skipped");
        after_scan_at(&p, &json!([row("c")]), &json!([row("c")])).unwrap();
        assert!(load_at(&p).contains_key("c"));
        assert!(set_state_at(&p, "c", "maybe", "", &row("c")).is_err());
    }
}
