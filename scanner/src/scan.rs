//! Scan a folder of projects and build the scope the sources API takes (the same output as
//! .claude/skills/supply-chain-advisor/scripts/scan_folders.py; tests compare the two).

use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::manifests::{is_manifest, lock_entries, lock_versions, manifest_deps};

/// Lockfiles reported per project (the server flags a project without one). Installed versions are read only from
/// uv.lock, bun.lock and package-lock.json (manifests.rs). Same list as scan_folders.py.
const LOCKFILES: [&str; 11] = [
    "uv.lock",
    "requirements.lock",
    "poetry.lock",
    "pdm.lock",
    "Pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
];
use crate::util::{abspath, basename, now_iso, read_text, relpath, sorted};
use crate::vendors::{detect, Rules};
use crate::walk;

/// Every file of a project the scanner looks at: skips dependency/build folders and dot-folders except .github.
fn files_in(project: &Path, rules: &Rules) -> Vec<PathBuf> {
    let skip = &rules.project_skip_dirs;
    // Python: `d not in SKIP and not d.startswith(".") or d == ".github"`
    walk::files(project, &|d| {
        (!skip.contains(d) && !d.starts_with('.')) || d == ".github"
    })
}

fn stack_of(files: &[PathBuf]) -> BTreeSet<String> {
    let rx = Regex::new(r"(?mi)^\s*FROM\s+([^\s:@]+)").unwrap();
    let mut out = BTreeSet::new();
    for f in files.iter().filter(|f| basename(f).starts_with("Dockerfile")) {
        for m in rx.captures_iter(&read_text(f, None)) {
            let img = m[1].rsplit('/').next().unwrap_or("").to_lowercase();
            if img != "scratch" && !img.starts_with('$') {
                out.insert(img);
            }
        }
    }
    out
}

/// Organisations of the CA certificates shipped in the project, with the file each is in (parsed here; nothing
/// is executed from the project).
fn cas_of(files: &[PathBuf]) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for f in files.iter().filter(|f| {
        let b = basename(f);
        b.ends_with(".pem") || b.ends_with(".crt")
    }) {
        for org in crate::certs::subject_orgs(&read_text(f, None)) {
            if !out.iter().any(|(p, o)| p == f && o == &org) {
                out.push((f.clone(), org));
            }
        }
    }
    out
}

fn internal_names(files: &[PathBuf]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for f in files.iter().filter(|f| basename(f) == "internal-packages.txt") {
        for l in read_text(f, None).lines() {
            if !l.trim().is_empty() && !l.starts_with('#') {
                out.insert(l.trim().to_string());
            }
        }
    }
    out
}

/// The projects in a folder: the folder itself if it has a manifest at its top, else each subfolder.
pub fn projects_in(root: &Path, rules: &Rules) -> Vec<PathBuf> {
    let root = abspath(root);
    let entries = walk::listdir(&root);
    let top_manifest = entries.iter().any(|(n, is_dir)| !is_dir && is_manifest(n));
    if top_manifest {
        return vec![root];
    }
    let mut out: Vec<PathBuf> = entries
        .into_iter()
        .filter(|(n, is_dir)| *is_dir && !n.starts_with('.') && !rules.project_skip_dirs.contains(n))
        .map(|(n, _)| root.join(n))
        .collect();
    out.sort();
    out
}

struct Package {
    manager: &'static str, // "pip" | "npm"
    name: String,
    versions: BTreeSet<String>,
    found_in: Vec<Value>,
}

/// -> (scope, projects): the scope JSON for POST /v1/scans and a per-project summary.
pub fn scan(root: &Path, rules: &Rules) -> (Value, Value) {
    let root_abs = abspath(root);
    let base_dir = root_abs.parent().map_or_else(|| root_abs.clone(), Path::to_path_buf);
    let rel = |p: &Path| relpath(p, &base_dir);
    // a list in the scanned folder itself also covers the projects in its subfolders (web/, api/, ...)
    let root_internal = internal_names(
        &[root_abs.join("internal-packages.txt")]
            .into_iter()
            .filter(|f| f.is_file())
            .collect::<Vec<_>>(),
    );
    let mut packages: BTreeMap<(String, String), Package> = BTreeMap::new();
    let mut vendors: BTreeMap<String, (String, BTreeSet<String>)> = BTreeMap::new(); // name -> (type, projects)
    let (mut stack, mut cas, mut internal) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let mut projects = Vec::new();
    let (mut secrets, mut cert_files) = (Vec::new(), Vec::new());

    for proj in projects_in(root, rules) {
        let name = basename(&proj);
        let files = files_in(&proj, rules);
        let locks = lock_versions(&files);
        let usage = crate::usage::scan(&files, &rules.import_aliases);
        let mut manifests: Vec<PathBuf> = files.iter().filter(|f| is_manifest(&basename(f))).cloned().collect();
        manifests.sort();
        let mut count = 0;
        for mf in &manifests {
            for d in manifest_deps(mf) {
                let mut version = d.version.clone();
                let mut how = if d.pinned { "pinned" } else { "range" };
                if !d.pinned {
                    if let Some(locked) = locks.get(&(d.ecosystem.to_string(), d.name.to_lowercase())) {
                        version = Some(locked.clone());
                        how = "lockfile";
                    } else if version.is_none() {
                        how = "unpinned (latest)";
                    }
                }
                let key = (d.ecosystem.to_string(), d.name.to_lowercase());
                let p = packages.entry(key).or_insert_with(|| Package {
                    manager: if d.ecosystem == "PyPI" { "pip" } else { "npm" },
                    name: d.name.clone(),
                    versions: BTreeSet::new(),
                    found_in: vec![],
                });
                if let Some(v) = &version {
                    p.versions.insert(v.clone());
                }
                p.found_in.push(
                    json!({"project": name, "file": rel(mf), "line": d.line, "text": d.text, "spec": d.spec,
                                       "version": version, "version_from": how, "section": d.section,
                                       "used": usage.used(d.ecosystem, &d.name)}),
                );
                count += 1;
            }
        }
        // every other package version the lockfiles pin: dependencies of dependencies (and direct ones locked at a
        // version the manifest doesn't name)
        let mut seen: BTreeSet<(String, String, String)> = packages
            .iter()
            .flat_map(|((eco, n), p)| {
                p.found_in
                    .iter()
                    .filter(|f| f["project"] == name.as_str())
                    .filter_map(|f| f["version"].as_str().map(|v| (eco.clone(), n.clone(), v.to_string())))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (eco, pkg, version, lockfile) in lock_entries(&files) {
            if !seen.insert((eco.clone(), pkg.to_lowercase(), version.clone())) {
                continue;
            }
            let p = packages
                .entry((eco.clone(), pkg.to_lowercase()))
                .or_insert_with(|| Package {
                    manager: if eco == "PyPI" { "pip" } else { "npm" },
                    name: pkg.clone(),
                    versions: BTreeSet::new(),
                    found_in: vec![],
                });
            p.versions.insert(version.clone());
            p.found_in.push(
                json!({"project": name, "file": rel(&lockfile), "line": null, "text": null, "spec": null,
                                   "version": version, "version_from": "lockfile", "section": "transitive",
                                   "used": usage.used(&eco, &pkg)}),
            );
        }
        let mut pv = Vec::new();
        for (vname, vtype) in detect(&proj, rules).unwrap_or_default() {
            let e = vendors
                .entry(vname.clone())
                .or_insert_with(|| (vtype.clone(), BTreeSet::new()));
            e.1.insert(name.clone());
            pv.push(Value::String(vname));
        }
        let (st, ca_files, mut intl) = (stack_of(&files), cas_of(&files), internal_names(&files));
        intl.extend(root_internal.iter().cloned());
        let ca: BTreeSet<String> = ca_files.iter().map(|(_, o)| o.clone()).collect();
        for (f, org) in &ca_files {
            cert_files.push(json!({"project": name, "file": rel(f), "ca": org}));
        }
        secrets.extend(crate::secrets::scan_project(&proj, &base_dir, &name, &rules.secrets));
        stack.extend(st.iter().cloned());
        cas.extend(ca.iter().cloned());
        internal.extend(intl.iter().cloned());
        let lockfiles = sorted(
            files
                .iter()
                .filter(|f| LOCKFILES.contains(&basename(f).as_str()))
                .map(|f| rel(f))
                .collect(),
        );
        projects.push(json!({"project": name, "path": rel(&proj), "manifests": manifests.iter().map(|m| rel(m)).collect::<Vec<_>>(),
                             "dependencies": count, "lockfiles": lockfiles, "vendors": pv,
                             "stack": st.into_iter().collect::<Vec<_>>(), "certificate_authorities": ca.into_iter().collect::<Vec<_>>(),
                             "internal_packages": intl.into_iter().collect::<Vec<_>>()}));
    }

    // Python sorts the package keys as (ecosystem, name): "PyPI" before "npm"
    let pkgs: Vec<Value> = packages
        .into_values()
        .map(|p| {
            let mut m = Map::new();
            m.insert("package_manager".into(), json!(p.manager));
            m.insert("name".into(), json!(p.name));
            m.insert("found_in".into(), Value::Array(p.found_in));
            m.insert("versions".into(), json!(p.versions.into_iter().collect::<Vec<_>>()));
            Value::Object(m)
        })
        .collect();
    let mut vlist: Vec<(String, String, BTreeSet<String>)> =
        vendors.into_iter().map(|(n, (t, ps))| (n, t, ps)).collect();
    vlist.sort_by_key(|a| a.0.to_lowercase());
    let scope = json!({
        "$comment": format!("Generated by ssc (Rust scanner) from {} on {}. Same format as intel_api/config/scope.json; found_in says where each package came from.",
                            root_abs.display(), now_iso()),
        "packages": pkgs,
        "vendors": vlist.into_iter().map(|(n, t, ps)| json!({"name": n, "aliases": [], "type": t, "projects": ps.into_iter().collect::<Vec<_>>()})).collect::<Vec<_>>(),
        "stack": stack.into_iter().collect::<Vec<_>>(),
        "certificate_authorities": cas.into_iter().collect::<Vec<_>>(),
        "internal_packages": internal.into_iter().collect::<Vec<_>>(),
        "base_dir": base_dir.display().to_string(),
        // facts only: which kind of secret, where, example or real, git status; never the value
        "secrets": secrets,
        "certificate_files": cert_files,
    });
    (scope, Value::Array(projects))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn rules() -> Rules {
        Rules::from_json(&serde_json::from_str(crate::app::RULES_BUILTIN).unwrap()).unwrap()
    }

    #[test]
    fn a_folder_with_a_manifest_on_top_is_one_project_else_each_subfolder() {
        let t = TempDir::new();
        t.write("ws/b/requirements.txt", "x==1\n");
        t.write("ws/a/package.json", "{}");
        t.write("ws/.hidden/package.json", "{}");
        t.write("ws/node_modules/y/package.json", "{}");
        t.write("ws/notes.txt", "");
        let names: Vec<String> = projects_in(&t.path().join("ws"), &rules())
            .iter()
            .map(|p| basename(p))
            .collect();
        assert_eq!(names, vec!["a", "b"]);
        assert_eq!(
            projects_in(&t.path().join("ws/b"), &rules()),
            vec![t.path().join("ws/b")]
        );
    }

    #[test]
    fn a_top_level_internal_list_covers_projects_in_subfolders() {
        let t = TempDir::new();
        t.write("app/internal-packages.txt", "ui-kit\n");
        t.write("app/web/package.json", "{\"dependencies\": {\"ui-kit\": \"1.0.0\"}}");
        t.write("app/api/requirements.txt", "flask==3.1.3\n");
        let (scope, projects) = scan(&t.path().join("app"), &rules());
        assert_eq!(scope["internal_packages"], json!(["ui-kit"]));
        for p in projects.as_array().unwrap() {
            assert_eq!(p["internal_packages"], json!(["ui-kit"]), "{}", p["project"]);
        }
    }

    #[test]
    fn scope_paths_are_relative_to_the_scanned_folders_parent() {
        let t = TempDir::new();
        t.write("ws/api/requirements.txt", "flask==3.1.3\nrequests>=2\n");
        t.write(
            "ws/api/uv.lock",
            "[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n",
        );
        t.write("ws/api/Dockerfile", "FROM python:3.12-slim\nFROM scratch\n");
        t.write("ws/api/internal-packages.txt", "# ours\nacme-core\n");
        let (scope, projects) = scan(&t.path().join("ws"), &rules());
        let pkgs = scope["packages"].as_array().unwrap();
        let names: Vec<&str> = pkgs.iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["flask", "requests"]);
        let req = &pkgs[1]["found_in"][0];
        assert_eq!(req["file"], "ws/api/requirements.txt");
        assert_eq!(req["line"], 2);
        assert_eq!(
            (req["version"].as_str(), req["version_from"].as_str()),
            (Some("2.32.0"), Some("lockfile"))
        );
        assert_eq!(pkgs[0]["package_manager"], "pip");
        assert_eq!(scope["stack"], json!(["python"]));
        assert_eq!(scope["internal_packages"], json!(["acme-core"]));
        assert_eq!(scope["base_dir"], t.path().display().to_string());
        assert_eq!(projects[0]["path"], "ws/api");
        assert_eq!(projects[0]["lockfiles"], json!(["ws/api/uv.lock"]));
        assert_eq!(projects[0]["dependencies"], 2);
    }
}
