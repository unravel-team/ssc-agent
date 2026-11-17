//! One scan of one folder: build the scope, send it, wait for the server's result, save it. Shared by the
//! command line and the UI; progress goes to a callback.

use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::{app, done, scan, util, vendors};

/// The detection rules: the API's current ones when it can be reached (cached), else the cached copy, else the built-in.
pub fn rules(api: Option<&app::Api>) -> vendors::Rules {
    let cache = app::dir().join("scanner_rules.json");
    if let Some(a) = api {
        if let Ok((200, v)) = a.call("GET", "/v1/scanner-rules", None) {
            if let Ok(r) = vendors::Rules::from_json(&v) {
                let _ = app::save_json(&cache, &v);
                return r;
            }
        }
    }
    // the built-in copy is checked by a unit test (`builtin_rules_parse`), so it can't fail here
    let builtin: Value = serde_json::from_str(app::RULES_BUILTIN).expect("built-in scanner_rules.json is valid JSON");
    // the cached copy unless the built-in one is newer: a copy cached by an older version must not hide newer rules
    let cached = std::fs::read_to_string(&cache)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(|v| version(v) >= version(&builtin))
        .and_then(|v| vendors::Rules::from_json(&v).ok());
    cached.unwrap_or_else(|| vendors::Rules::from_json(&builtin).expect("built-in scanner_rules.json has valid rules"))
}

fn version(rules: &Value) -> i64 {
    rules["version"].as_i64().unwrap_or(0)
}

fn count(v: &Value) -> usize {
    v.as_array().map_or(0, Vec::len)
}

/// Scan `folder`, send it, wait for the advisory, save it. -> the server's result for the scan.
pub fn scan_folder(
    api: &app::Api,
    rules: &vendors::Rules,
    folder: &Path,
    progress: &dyn Fn(&str),
) -> Result<Value, String> {
    let label = app::folder_label(folder);
    if !folder.is_dir() {
        return Err(format!("{label}: not a folder"));
    }
    let t0 = Instant::now();
    let (mut scope, projects) = scan::scan(folder, rules);
    // the server needs no local paths: file paths in found_in are relative to the scanned folder
    if let Some(m) = scope.as_object_mut() {
        m.remove("base_dir");
        m.remove("$comment");
        m.insert("projects".into(), projects);
    }
    progress(&format!(
        "{} package(s) found in {:.1}s; sending to the server",
        count(&scope["packages"]),
        t0.elapsed().as_secs_f32()
    ));
    // the items ticked off here (with their names, which the server may no longer list), so the advisory doesn't
    // ask again for what is already done
    let done: Vec<Value> = done::load(&label)
        .iter()
        .map(|(k, v)| {
            let mut d = json!({"key": k, "project": v["row"]["project"], "item": v["row"]["item"],
                               "action": v["row"]["action"], "kind": v["row"]["kind"], "state": done::state_of(Some(v))});
            if let Some(why) = v["why"].as_str() {
                d["why"] = json!(why);
            }
            d
        })
        .collect();
    let body = json!({"folder": label, "device_name": util::device_name(), "scope": scope, "done": done});
    let (st, r) = api.call("POST", "/v1/scans", Some(&body))?;
    if st != 200 {
        return Err(format!(
            "the server refused the scan ({st}): {}",
            r["error"].as_str().unwrap_or("")
        ));
    }
    let (id, poll) = (
        r["id"].as_str().unwrap_or("").to_string(),
        r["poll"].as_str().unwrap_or("").to_string(),
    );
    let (deadline, mut last) = (Instant::now() + Duration::from_mins(25), String::new());
    let result = loop {
        std::thread::sleep(Duration::from_secs(2));
        let (st, s) = api.call("GET", &poll, None)?;
        if st != 200 {
            return Err(format!(
                "checking scan {id} failed ({st}): {}",
                s["error"].as_str().unwrap_or("")
            ));
        }
        let status = s["status"].as_str().unwrap_or("").to_string();
        let what = match status.as_str() {
            "queued" => "waiting for the server",
            "assessing" => "checking every package against the database and the rules",
            "advising" | "agent_running" => "the agents are writing the advisory (about a minute)",
            _ => "",
        };
        if !what.is_empty() && what != last {
            progress(what);
            last = what.to_string();
        }
        if status == "done" || status == "failed" {
            break s;
        }
        if Instant::now() > deadline {
            return Err(format!("no result after 25 minutes (scan {id}); check again later"));
        }
    };
    if result["status"] == "failed" {
        return Err(format!(
            "the server could not assess the scan: {}",
            result["error"].as_str().unwrap_or("")
        ));
    }
    let mut state = app::load_state();
    // what the previous scan listed, to tick what this one no longer finds
    let previous: Value = state[&label]["dir"]
        .as_str()
        .and_then(|d| std::fs::read_to_string(Path::new(d).join("result.json")).ok())
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .map_or(Value::Null, |r| r["actions"].clone());
    let saved = app::save_result(&label, &result)?;
    let fixed = if previous.is_array() {
        done::after_scan(&label, &previous, &result["actions"])?
    } else {
        0
    };
    state[&label] = json!({"folder": folder.display().to_string(), "scan_id": id, "at": util::now_iso(),
                            "summary": result["summary"], "advice_status": result["advice_status"],
                            "dir": saved.display().to_string(), "advice": saved.join("ADVICE.md").display().to_string(),
                            "new": count(&result["changes"]["new"]), "resolved": count(&result["changes"]["resolved"]),
                            "first_scan": result["changes"]["first_scan"]});
    app::save_json(&app::dir().join("state.json"), &state)?;
    let s = &result["summary"];
    let ticked = done::load(&label);
    let open = result["actions"].as_array().map_or(0, |a| {
        a.iter()
            .filter(|r| !ticked.contains_key(r["key"].as_str().unwrap_or("")))
            .count()
    });
    progress(&format!(
        "done: BLOCK {} · HOLD {} · ALLOW {} · {} action item(s) open{} · advice {}",
        s["BLOCK"],
        s["HOLD"],
        s["ALLOW"],
        open,
        if fixed > 0 {
            format!(", {fixed} fixed since the last scan")
        } else {
            String::new()
        },
        result["advice_status"].as_str().unwrap_or("")
    ));
    Ok(result)
}

/// One scan at a time (background, command line and UI must not overlap).
pub fn lock() -> Option<std::fs::File> {
    let p = app::dir().join("scan.lock");
    std::fs::create_dir_all(app::dir()).ok()?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&p)
        .ok()?;
    f.try_lock().ok().map(|()| f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_parse() {
        // runner::rules falls back to these with expect(): they must always load
        let v: Value = serde_json::from_str(app::RULES_BUILTIN).unwrap();
        let r = vendors::Rules::from_json(&v).unwrap();
        assert!(r.skip_dirs.contains("node_modules"));
        assert!(r.project_skip_dirs.contains("node_modules"));
    }

    #[test]
    fn an_older_cached_copy_does_not_hide_newer_built_in_rules() {
        let builtin: Value = serde_json::from_str(app::RULES_BUILTIN).unwrap();
        let mut old = builtin.clone();
        old["version"] = json!(version(&builtin) - 1);
        assert!(version(&old) < version(&builtin));
        assert_eq!(version(&json!({})), 0); // a copy without a version is the oldest
    }

    #[test]
    fn count_is_zero_for_non_arrays() {
        assert_eq!(count(&json!([1, 2])), 2);
        assert_eq!(count(&json!(null)), 0);
        assert_eq!(count(&json!({"a": 1})), 0);
    }
}
