//! Secrets in a project's files (the key guardian's patterns, from the shared rules). Only facts leave the laptop:
//! which kind, which file and line, whether it looks like an example value, whether git tracks or ignores the file.
//! The value itself is never kept, printed or sent, not even masked.

use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::util::{basename, relpath, run};
use crate::walk;

pub struct SecretRules {
    patterns: Vec<(String, String, Regex)>, // kind, severity, pattern
    placeholder: Regex,
    skip: HashSet<String>,
}

impl SecretRules {
    pub fn from_json(v: &Value) -> Result<SecretRules, String> {
        let mut patterns = Vec::new();
        for r in v
            .get("secret_patterns")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
            patterns.push((
                s("kind"),
                s("severity"),
                Regex::new(&s("pattern")).map_err(|e| e.to_string())?,
            ));
        }
        let ph = v
            .get("secret_placeholder")
            .and_then(|x| x.as_str())
            .unwrap_or("(?i)example|dummy|fake|placeholder|xxxx");
        Ok(SecretRules {
            patterns,
            placeholder: RegexBuilder::new(ph).build().map_err(|e| e.to_string())?,
            skip: v
                .get("secret_skip_dirs")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
        })
    }
}

const MAX_FILE: u64 = 2 * 1024 * 1024;

fn text_of(p: &Path) -> Option<String> {
    let meta = std::fs::metadata(p).ok()?;
    // regular files only: a FIFO or a link to /dev/zero reports a size of 0 and would never end
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    // read at most MAX_FILE + 1 bytes, in case the file grew since its size was checked
    let mut bytes = Vec::new();
    std::fs::File::open(p)
        .ok()?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_FILE || bytes.iter().take(8000).any(|&b| b == 0) {
        return None; // binary
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// git's view of each file with a finding: (tracked, ignored); None when it isn't a git repo or git isn't installed.
fn git_status(project: &Path, rel: &str) -> Option<(bool, bool)> {
    let dir = project.to_string_lossy().to_string();
    let (ok, out, _) = run("git", &["-C", &dir, "rev-parse", "--is-inside-work-tree"], None);
    if !ok || out.trim() != "true" {
        return None;
    }
    let tracked = !run("git", &["-C", &dir, "ls-files", "--", rel], None)
        .1
        .trim()
        .is_empty();
    let ignored = run("git", &["-C", &dir, "check-ignore", "-q", "--", rel], None).0;
    Some((tracked, ignored))
}

/// Secrets found in one project. `base` is what file paths are made relative to (the scanned folder's parent).
pub fn scan_project(project: &Path, base: &Path, name: &str, rules: &SecretRules) -> Vec<Value> {
    let skip = &rules.skip;
    let files: Vec<PathBuf> = walk::files(project, &|d| !skip.contains(d));
    let mut found: BTreeMap<(String, usize, String), Value> = BTreeMap::new();
    let mut status_cache: BTreeMap<String, Option<(bool, bool)>> = BTreeMap::new();
    for f in &files {
        let Some(text) = text_of(f) else { continue };
        let fname = basename(f);
        let env_file = fname.starts_with(".env");
        for (i, line) in text.lines().enumerate() {
            for (kind, severity, rx) in &rules.patterns {
                for m in rx.find_iter(line) {
                    let value = m.as_str();
                    if kind == "OpenAI API key" && value.starts_with("sk-ant-") {
                        continue; // an Anthropic key, matched by its own pattern
                    }
                    let file = relpath(f, base);
                    let key = (file.clone(), i + 1, kind.clone());
                    if found.contains_key(&key) {
                        continue;
                    }
                    let in_project = relpath(f, project);
                    let git = *status_cache
                        .entry(in_project.clone())
                        .or_insert_with(|| git_status(project, &in_project));
                    let mut s = json!({"project": name, "file": file, "line": i + 1, "kind": kind, "severity": severity,
                                       "placeholder": rules.placeholder.is_match(value), "in_source_code": !env_file,
                                       "env_file": env_file});
                    if let Some((tracked, ignored)) = git {
                        s["tracked"] = json!(tracked);
                        s["ignored"] = json!(ignored);
                    }
                    found.insert(key, s);
                }
            }
        }
    }
    found.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn rules() -> SecretRules {
        let v: Value = serde_json::from_str(crate::app::RULES_BUILTIN).unwrap();
        SecretRules::from_json(&v).unwrap()
    }

    // built at run time so this file holds no secret-shaped strings itself
    fn openai_key() -> String {
        format!("sk-proj-{}", "A1b2C3d4".repeat(5))
    }
    fn anthropic_key() -> String {
        format!("sk-ant-api03-{}", "Z9y8X7w6".repeat(4))
    }
    fn aws_id() -> String {
        format!("AKIA{}", "Q".repeat(16))
    }

    fn scan(t: &TempDir) -> Vec<Value> {
        let project = t.path().join("proj");
        scan_project(&project, t.path(), "proj", &rules())
    }

    #[test]
    fn finds_kind_file_and_line_and_never_the_value() {
        let t = TempDir::new();
        let (oa, an, aws) = (openai_key(), anthropic_key(), aws_id());
        t.write(
            "proj/app/config.py",
            format!("import os\nOPENAI = '{oa}'\nX = 1\nAWS = \"{aws}\"\n"),
        );
        t.write("proj/.env", format!("ANTHROPIC_API_KEY={an}\n"));
        let found = scan(&t);
        let facts: Vec<(String, u64, String)> = found
            .iter()
            .map(|s| {
                (
                    s["file"].as_str().unwrap().to_string(),
                    s["line"].as_u64().unwrap(),
                    s["kind"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            facts,
            vec![
                ("proj/.env".into(), 1, "Anthropic API key".into()),
                ("proj/app/config.py".into(), 2, "OpenAI API key".into()),
                ("proj/app/config.py".into(), 4, "AWS access key ID".into()),
            ]
        );
        let env = &found[0];
        assert_eq!(env["env_file"], true);
        assert_eq!(env["in_source_code"], false);
        assert_eq!(env["project"], "proj");
        assert_eq!(env["severity"], "CRITICAL");
        assert_eq!(found[1]["in_source_code"], true);

        // the whole output, as it would be sent, holds none of the values (not even a part of one)
        let out = serde_json::to_string(&found).unwrap();
        for secret in [&oa, &an, &aws] {
            assert!(!out.contains(secret.as_str()), "a secret value leaked");
            assert!(
                !out.contains(&secret[secret.len() - 12..]),
                "part of a secret value leaked"
            );
        }
        let allowed = [
            "project",
            "file",
            "line",
            "kind",
            "severity",
            "placeholder",
            "in_source_code",
            "env_file",
            "tracked",
            "ignored",
        ];
        for s in &found {
            for k in s.as_object().unwrap().keys() {
                assert!(allowed.contains(&k.as_str()), "unexpected field {k}");
            }
        }
    }

    #[test]
    fn an_anthropic_key_is_not_also_reported_as_an_openai_key() {
        let t = TempDir::new();
        t.write("proj/a.txt", anthropic_key());
        let kinds: Vec<Value> = scan(&t).into_iter().map(|s| s["kind"].clone()).collect();
        assert_eq!(kinds, vec![Value::from("Anthropic API key")]);
    }

    #[test]
    fn one_finding_per_file_line_and_kind() {
        let t = TempDir::new();
        let k = aws_id();
        t.write("proj/a.txt", format!("{k} {k} {k}\n"));
        assert_eq!(scan(&t).len(), 1);
    }

    #[test]
    fn placeholder_values_are_marked() {
        let t = TempDir::new();
        t.write("proj/a.txt", format!("sk-proj-EXAMPLE{}\n", "x".repeat(30)));
        let found = scan(&t);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["placeholder"], true);
    }

    #[test]
    fn skips_binary_files_big_files_and_skip_dirs() {
        let t = TempDir::new();
        let k = aws_id();
        t.write("proj/bin.dat", [k.as_bytes(), b"\0"].concat());
        t.write("proj/node_modules/x/index.js", &k);
        t.write("proj/.git/config", &k);
        let mut big = k.clone().into_bytes();
        big.resize(usize::try_from(MAX_FILE).unwrap() + 1, b' ');
        t.write("proj/big.txt", big);
        assert_eq!(scan(&t), Vec::<Value>::new());
    }

    #[test]
    fn rules_without_secret_settings_use_the_default_placeholder() {
        let r = SecretRules::from_json(&serde_json::json!({})).unwrap();
        assert!(r.patterns.is_empty() && r.skip.is_empty());
        assert!(r.placeholder.is_match("DUMMY"));
    }

    #[test]
    fn a_bad_pattern_is_an_error_not_a_panic() {
        let v = serde_json::json!({"secret_patterns": [{"kind": "x", "severity": "LOW", "pattern": "("}]});
        assert!(SecretRules::from_json(&v).is_err());
    }
}
