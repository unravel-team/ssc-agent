//! Small helpers: file reading, paths, time, running the system's tools.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Read a file as text: invalid UTF-8 is dropped, at most `limit` characters (like Python's
/// `open(errors="ignore").read(limit)`). Only regular files are read (following symlinks): a FIFO, or a link to
/// /dev/zero, in a scanned project would otherwise never end.
pub fn read_text(path: &Path, limit: Option<usize>) -> String {
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return String::new();
    }
    if let Some(n) = limit {
        // A prefix of 4n+8 bytes holds the first n characters unless much of it is invalid UTF-8; only the last
        // character or two can depend on bytes after it (a "\r\n" or a multi-byte character cut in two).
        let cap = n.saturating_mul(4).saturating_add(8);
        let mut prefix = Vec::new();
        let read = std::fs::File::open(path).and_then(|f| f.take(cap as u64).read_to_end(&mut prefix));
        if read.is_err() {
            return String::new();
        }
        let text = decode_text(&prefix);
        if prefix.len() < cap || text.chars().count() > n + 1 {
            return truncate_chars(text, n);
        }
    }
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let text = decode_text(&bytes);
    match limit {
        Some(n) => truncate_chars(text, n),
        None => text,
    }
}

/// UTF-8 with invalid bytes dropped and Python's universal newlines ("\r\n" and "\r" become "\n").
fn decode_text(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        s.push_str(chunk.valid());
    }
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn truncate_chars(s: String, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((at, _)) => s[..at].to_string(),
        None => s,
    }
}

/// Lines like Python's `str.splitlines()` for normal text files.
pub fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

/// An absolute, normalised path (like Python's os.path.abspath: no symlinks resolved).
pub fn abspath(p: &Path) -> PathBuf {
    let base = if p.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    let mut out = PathBuf::new();
    for c in base.join(p).components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `path` relative to `base` (both absolute), with "/" separators.
pub fn relpath(path: &Path, base: &Path) -> String {
    match path.strip_prefix(base) {
        Ok(r) => r.to_string_lossy().replace('\\', "/"),
        Err(_) => path.to_string_lossy().to_string(),
    }
}

pub fn basename(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Now as ISO 8601 UTC with seconds, like Python's datetime.now(timezone.utc).isoformat(timespec="seconds").
pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Run a tool, feed it `input` on stdin, return (exit ok, stdout, stderr).
pub fn run(cmd: &str, args: &[&str], input: Option<&[u8]>) -> (bool, String, String) {
    let mut c = Command::new(cmd);
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    c.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => return (false, String::new(), format!("{cmd}: {e}")),
    };
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        // a write error shows up as the tool failing; stdin is closed when it goes out of scope here
        let _ = stdin.write_all(data);
    }
    match child.wait_with_output() {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).to_string(),
            String::from_utf8_lossy(&o.stderr).to_string(),
        ),
        Err(e) => (false, String::new(), e.to_string()),
    }
}

pub fn home() -> PathBuf {
    let h = std::env::var("HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("USERPROFILE").ok());
    PathBuf::from(h.unwrap_or_else(|| ".".into()))
}

/// This computer's name, for showing in results (any OS).
pub fn device_name() -> String {
    if let Ok(n) = std::env::var("COMPUTERNAME") {
        return n; // Windows
    }
    let (ok, out, _) = run("hostname", &[], None);
    if ok && !out.trim().is_empty() {
        out.trim().to_string()
    } else {
        "computer".into()
    }
}

/// A random hex token: the OS random source where there is one, else std's randomly seeded hashers.
pub fn random_token() -> String {
    let mut buf = [0u8; 16];
    let from_os = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !from_os {
        use std::hash::{BuildHasher, Hasher};
        for chunk in buf.chunks_mut(8) {
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u128(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
            chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
        }
    }
    buf.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = write!(s, "{b:02x}"); // writing to a String can't fail
        s
    })
}

/// Write a file only this user can read (the API key).
pub fn write_private(path: &Path, data: &str) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    // a file that was already there keeps its old mode on open: make it private before the data goes in
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(data.as_bytes())
}

/// Python's `sorted(set(...))` on strings: by code point (same as UTF-8 byte order), duplicates dropped.
pub fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

/// A temporary folder for tests, removed when dropped (std only: no test crates).
#[cfg(test)]
pub struct TempDir(PathBuf);

#[cfg(test)]
impl TempDir {
    pub fn new() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("ssc-test-{}-{n}-{}", std::process::id(), random_token()));
        std::fs::create_dir_all(&p).expect("create a temp folder");
        TempDir(abspath(&p))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Write `rel` (creating its folders) and return its path.
    pub fn write(&self, rel: &str, data: impl AsRef<[u8]>) -> PathBuf {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().expect("a file has a parent")).expect("create folders");
        std::fs::write(&p, data).expect("write a test file");
        p
    }
}

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_text_drops_invalid_utf8_and_normalises_newlines() {
        let t = TempDir::new();
        let f = t.write("a.txt", b"one\r\ntwo\rthree\xff\xfe\nfour");
        assert_eq!(read_text(&f, None), "one\ntwo\nthree\nfour");
    }

    #[test]
    fn read_text_limit_counts_characters_like_python() {
        let t = TempDir::new();
        let f = t.write("a.txt", "héllo wörld\r\nmore");
        assert_eq!(read_text(&f, Some(5)), "héllo");
        assert_eq!(read_text(&f, Some(12)), "héllo wörld\n");
        assert_eq!(read_text(&f, Some(1000)), "héllo wörld\nmore");
        assert_eq!(read_text(&f, Some(0)), "");
    }

    #[test]
    fn read_text_limit_matches_a_full_read_on_a_large_file() {
        // the prefix read must give the same characters as reading everything and cutting
        let t = TempDir::new();
        let body: String = (0..20_000).map(|i| if i % 7 == 0 { "ü\r\n" } else { "ab" }).collect();
        let f = t.write("big.txt", &body);
        let full = read_text(&f, None);
        for n in [1, 99, 100, 4_096, 30_000] {
            assert_eq!(
                read_text(&f, Some(n)),
                full.chars().take(n).collect::<String>(),
                "limit {n}"
            );
        }
    }

    #[test]
    fn read_text_limit_falls_back_when_the_prefix_is_mostly_invalid() {
        let t = TempDir::new();
        let mut data = vec![0xffu8; 100];
        data.extend_from_slice(b"ok");
        let f = t.write("junk.bin", data);
        assert_eq!(read_text(&f, Some(2)), "ok");
    }

    #[test]
    fn read_text_skips_missing_files_and_folders() {
        let t = TempDir::new();
        assert_eq!(read_text(&t.path().join("nope"), None), "");
        assert_eq!(read_text(t.path(), Some(10)), "");
    }

    #[cfg(unix)]
    #[test]
    fn read_text_does_not_read_devices() {
        // a project could hold a link to /dev/zero: reading it would never end
        let t = TempDir::new();
        let link = t.path().join("Dockerfile");
        std::os::unix::fs::symlink("/dev/zero", &link).expect("symlink");
        assert_eq!(read_text(&link, None), "");
    }

    #[test]
    fn abspath_normalises_without_touching_the_disk() {
        let base = if cfg!(windows) { "C:\\a" } else { "/a" };
        let p = abspath(&Path::new(base).join("b/./c/../d"));
        assert_eq!(p, Path::new(base).join("b").join("d"));
        assert!(abspath(Path::new("rel")).is_absolute());
    }

    #[test]
    fn relpath_uses_forward_slashes_and_falls_back_to_the_path() {
        let base = Path::new("/w");
        assert_eq!(relpath(&Path::new("/w").join("p").join("f.txt"), base), "p/f.txt");
        assert_eq!(relpath(Path::new("/other/f.txt"), base), "/other/f.txt");
    }

    #[test]
    fn basename_of_root_is_empty() {
        assert_eq!(basename(Path::new("/a/b.txt")), "b.txt");
        assert_eq!(basename(Path::new("/")), "");
    }

    #[test]
    fn now_iso_has_the_python_shape() {
        let s = now_iso();
        assert_eq!(s.len(), "2026-01-01T00:00:00+00:00".len(), "{s}");
        assert!(s.ends_with("+00:00"));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
        assert!(s[..4].parse::<u32>().unwrap() >= 2024);
    }

    #[test]
    fn random_tokens_are_hex_and_differ() {
        let (a, b) = (random_token(), random_token());
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn sorted_sorts_by_code_point_and_drops_duplicates() {
        let v = vec!["b".into(), "B".into(), "a".into(), "b".into()];
        assert_eq!(sorted(v), vec!["B", "a", "b"]);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_makes_the_file_owner_only_even_if_it_existed() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new();
        let f = t.write("sub/key", "old");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&f, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        let g = t.path().join("fresh/key");
        write_private(&g, "k").unwrap();
        assert_eq!(std::fs::metadata(&g).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn run_feeds_stdin_and_reports_a_missing_tool() {
        let (ok, _, err) = run("ssc-no-such-tool-xyz", &[], None);
        assert!(!ok);
        assert!(err.contains("ssc-no-such-tool-xyz"));
        if cfg!(unix) {
            let (ok, out, _) = run("cat", &[], Some(b"hello"));
            assert!(ok);
            assert_eq!(out, "hello");
        }
    }
}
