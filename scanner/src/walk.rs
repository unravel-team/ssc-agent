//! Folder walking in the same order as Python's os.walk (top-down; a folder's files, then its subfolders,
//! both in the order the file system lists them), so the Rust and Python scanners see files identically.

use std::path::{Path, PathBuf};

/// Every file under `root` (absolute paths). `keep_dir(name)` decides whether to descend into a folder.
pub fn files(root: &Path, keep_dir: &dyn Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, keep_dir, &mut out);
    out
}

fn walk(dir: &Path, keep_dir: &dyn Fn(&str) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let (mut subdirs, mut fs) = (Vec::new(), Vec::new());
    for e in entries.flatten() {
        let path = e.path();
        // like os.scandir's is_dir(): follows symlinks; os.walk then lists a symlinked folder but doesn't enter it
        let is_dir = std::fs::metadata(&path).is_ok_and(|m| m.is_dir());
        if is_dir {
            let is_link = e.file_type().is_ok_and(|t| t.is_symlink());
            let name = e.file_name().to_string_lossy().to_string();
            if keep_dir(&name) && !is_link {
                subdirs.push(path);
            }
        } else {
            fs.push(path);
        }
    }
    out.extend(fs);
    for d in subdirs {
        walk(&d, keep_dir, out);
    }
}

/// Names directly in a folder (files and folders), in file-system order.
pub fn listdir(dir: &Path) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let is_dir = std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir());
            out.push((e.file_name().to_string_lossy().to_string(), is_dir));
        }
    }
    out
}

/// The few glob patterns the rules use ("railway.json", ".github/workflows/*.y*ml", ".claude/*"): literal folders,
/// then `*` wildcards in the last part. Like Python's glob, `*` doesn't match names starting with ".".
pub fn glob_any(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let parts: Vec<&str> = pattern.split('/').collect();
    let Some((last, dirs)) = parts.split_last() else {
        return vec![];
    };
    let mut base = root.to_path_buf();
    for d in dirs {
        base.push(d);
    }
    if !last.contains('*') {
        let p = base.join(last);
        return if std::fs::symlink_metadata(&p).is_ok() {
            vec![p]
        } else {
            vec![]
        };
    }
    // the patterns come from the server's rules: one that can't be compiled matches nothing
    let Ok(rx) = regex::Regex::new(&format!("^{}$", regex::escape(last).replace(r"\*", ".*"))) else {
        return vec![];
    };
    let mut hits: Vec<PathBuf> = listdir(&base)
        .into_iter()
        .filter(|(n, _)| !n.starts_with('.') && rx.is_match(n))
        .map(|(n, _)| base.join(n))
        .collect();
    hits.sort();
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{relpath, TempDir};

    fn rel_files(t: &TempDir, keep_dir: &dyn Fn(&str) -> bool) -> Vec<String> {
        let mut v: Vec<String> = files(t.path(), keep_dir).iter().map(|p| relpath(p, t.path())).collect();
        v.sort();
        v
    }

    #[test]
    fn walks_everything_except_the_folders_it_is_told_to_skip() {
        let t = TempDir::new();
        for f in [
            "a.txt",
            "src/b.py",
            "src/deep/c.js",
            "node_modules/x/index.js",
            ".git/config",
            ".github/ci.yml",
        ] {
            t.write(f, "x");
        }
        let skip = ["node_modules", ".git"];
        assert_eq!(
            rel_files(&t, &|d| !skip.contains(&d)),
            vec![".github/ci.yml", "a.txt", "src/b.py", "src/deep/c.js"]
        );
        assert_eq!(rel_files(&t, &|_| false), vec!["a.txt"]);
    }

    #[test]
    fn a_folders_files_come_before_its_subfolders() {
        let t = TempDir::new();
        t.write("sub/inner.txt", "x");
        t.write("top.txt", "x");
        let got: Vec<String> = files(t.path(), &|_| true)
            .iter()
            .map(|p| relpath(p, t.path()))
            .collect();
        assert_eq!(got, vec!["top.txt", "sub/inner.txt"]);
    }

    #[test]
    fn a_missing_folder_has_no_files() {
        assert_eq!(
            files(Path::new("/no/such/folder/ssc"), &|_| true),
            Vec::<PathBuf>::new()
        );
        assert_eq!(listdir(Path::new("/no/such/folder/ssc")), Vec::<(String, bool)>::new());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_folders_are_listed_but_not_entered_so_loops_end() {
        let t = TempDir::new();
        t.write("real/f.txt", "x");
        std::os::unix::fs::symlink(t.path(), t.path().join("real/loop")).unwrap();
        std::os::unix::fs::symlink(t.path().join("real/f.txt"), t.path().join("link.txt")).unwrap();
        // a link to a folder is skipped (like os.walk); a link to a file is a file
        assert_eq!(rel_files(&t, &|_| true), vec!["link.txt", "real/f.txt"]);
        let names: Vec<(String, bool)> = {
            let mut v = listdir(&t.path().join("real"));
            v.sort();
            v
        };
        assert_eq!(names, vec![("f.txt".into(), false), ("loop".into(), true)]);
    }

    #[test]
    fn glob_literal_and_wildcards_like_python() {
        let t = TempDir::new();
        for f in [
            "railway.json",
            ".github/workflows/ci.yml",
            ".github/workflows/cd.yaml",
            ".github/workflows/.hidden.yml",
            ".github/workflows/notes.txt",
            ".claude/settings.json",
        ] {
            t.write(f, "x");
        }
        let rel = |p: &str| -> Vec<String> { glob_any(t.path(), p).iter().map(|h| relpath(h, t.path())).collect() };
        assert_eq!(rel("railway.json"), vec!["railway.json"]);
        assert_eq!(rel("fly.toml"), Vec::<String>::new());
        assert_eq!(
            rel(".github/workflows/*.y*ml"),
            vec![".github/workflows/cd.yaml", ".github/workflows/ci.yml"]
        );
        assert_eq!(rel(".claude/*"), vec![".claude/settings.json"]);
        assert_eq!(rel("nowhere/*"), Vec::<String>::new());
    }
}
