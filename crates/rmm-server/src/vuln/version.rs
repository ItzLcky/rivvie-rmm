//! Version comparison per packaging scheme, and "is this installed version in that range".
//!
//! Each comparer follows its package manager's own code, not a generic "semver-ish" rule:
//! - [`dpkg`]: `lib/dpkg/version.c` (epoch, upstream, revision; `~` sorts before everything,
//!   even the end of the string).
//! - [`rpm`]: `rpmio/rpmvercmp.c` (alphanumeric segments, `~` before and `^` after) plus the
//!   epoch, and the release when both sides have one.
//! - [`pacman`]: `lib/libalpm/version.c`, an older rpmvercmp that also weighs separators and
//!   never lets a trailing alpha segment beat an empty one; the release only when both have one.
//! - [`apk`]: `src/version.c` of apk-tools (digits, a letter, `_alpha`..`_p` suffixes, `-rN`).
//! - [`dotted`]: Windows `DisplayVersion`s and NVD ranges: numeric components, missing ones 0.
//!
//! The tests use vectors from dpkg's, rpm's, pacman's and apk-tools' own test suites.

use std::cmp::Ordering;

/// Which comparer an ecosystem uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Dotted,
}

impl Scheme {
    pub fn cmp(self, a: &str, b: &str) -> Ordering {
        match self {
            Scheme::Dpkg => dpkg(a, b),
            Scheme::Rpm => rpm(a, b),
            Scheme::Pacman => pacman(a, b),
            Scheme::Apk => apk(a, b),
            Scheme::Dotted => dotted(a, b),
        }
    }
}

/// One affected range: from `introduced` (None or `0`: the beginning; exclusive when
/// `introduced_exclusive`, as NVD's `versionStartExcluding`) up to but not including `fixed`,
/// or up to and including `last_affected`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Range {
    pub introduced: Option<String>,
    pub introduced_exclusive: bool,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

impl Range {
    pub fn contains(&self, scheme: Scheme, v: &str) -> bool {
        if let Some(i) = self.introduced.as_deref().filter(|i| !i.is_empty() && *i != "0") {
            match scheme.cmp(v, i) {
                Ordering::Less => return false,
                Ordering::Equal if self.introduced_exclusive => return false,
                _ => {}
            }
        }
        if let Some(f) = self.fixed.as_deref().filter(|f| !f.is_empty())
            && scheme.cmp(v, f) != Ordering::Less
        {
            return false;
        }
        if let Some(l) = self.last_affected.as_deref().filter(|l| !l.is_empty())
            && scheme.cmp(v, l) == Ordering::Greater
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// dpkg
// ---------------------------------------------------------------------------

/// `[epoch:]upstream[-revision]`, compared as dpkg does.
pub fn dpkg(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = dpkg_parts(a);
    let (eb, ub, rb) = dpkg_parts(b);
    ea.cmp(&eb).then_with(|| verrevcmp(ua, ub)).then_with(|| verrevcmp(ra, rb))
}

fn dpkg_parts(v: &str) -> (u64, &str, &str) {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit()) => (e.parse().unwrap_or(u64::MAX), r),
        _ => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((u, r)) => (epoch, u, r),
        None => (epoch, rest, ""),
    }
}

fn dpkg_order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(b'~') => -1,
        Some(c) => c as i32 + 256,
    }
}

fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let digit = |s: &[u8], k: usize| s.get(k).is_some_and(u8::is_ascii_digit);
    while i < a.len() || j < b.len() {
        let mut first_diff: i32 = 0;
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let ac = dpkg_order(a.get(i).copied());
            let bc = dpkg_order(b.get(j).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        while digit(a, i) && digit(b, j) {
            if first_diff == 0 {
                first_diff = a[i] as i32 - b[j] as i32;
            }
            i += 1;
            j += 1;
        }
        if digit(a, i) {
            return Ordering::Greater;
        }
        if digit(b, j) {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

// ---------------------------------------------------------------------------
// rpm
// ---------------------------------------------------------------------------

/// `[epoch:]version[-release]`: the epoch (missing = 0), then the version, then the release
/// when both sides name one.
pub fn rpm(a: &str, b: &str) -> Ordering {
    let (ea, va, ra) = evr(a);
    let (eb, vb, rb) = evr(b);
    let ea: u64 = ea.parse().unwrap_or(0);
    let eb: u64 = eb.parse().unwrap_or(0);
    ea.cmp(&eb).then_with(|| rpmvercmp(va, vb)).then_with(|| match (ra, rb) {
        (Some(x), Some(y)) => rpmvercmp(x, y),
        _ => Ordering::Equal,
    })
}

/// Epoch (`"0"` when absent), version, release. The epoch is the leading digits before a `:`.
fn evr(v: &str) -> (&str, &str, Option<&str>) {
    let v = v.trim();
    let digits = v.bytes().take_while(u8::is_ascii_digit).count();
    let (epoch, rest) = if v.as_bytes().get(digits) == Some(&b':') {
        (if digits == 0 { "0" } else { &v[..digits] }, &v[digits + 1..])
    } else {
        ("0", v)
    };
    match rest.rsplit_once('-') {
        Some((ver, rel)) => (epoch, ver, Some(rel)),
        None => (epoch, rest, None),
    }
}

/// rpm's `rpmvercmp`, with `~` (sorts before anything) and `^` (after the base, before more).
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    while i < a.len() || j < b.len() {
        while i < a.len() && sep(a[i]) {
            i += 1;
        }
        while j < b.len() && sep(b[j]) {
            j += 1;
        }
        let (ca, cb) = (a.get(i).copied(), b.get(j).copied());
        if ca == Some(b'~') || cb == Some(b'~') {
            if ca != Some(b'~') {
                return Ordering::Greater;
            }
            if cb != Some(b'~') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if ca == Some(b'^') || cb == Some(b'^') {
            if ca.is_none() {
                return Ordering::Less;
            }
            if cb.is_none() {
                return Ordering::Greater;
            }
            if ca != Some(b'^') {
                return Ordering::Greater;
            }
            if cb != Some(b'^') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if ca.is_none() || cb.is_none() {
            break;
        }
        let isnum = a[i].is_ascii_digit();
        let class = |c: &u8| if isnum { c.is_ascii_digit() } else { c.is_ascii_alphabetic() };
        let ea = i + a[i..].iter().take_while(|c| class(c)).count();
        let eb = j + b[j..].iter().take_while(|c| class(c)).count();
        if eb == j {
            return if isnum { Ordering::Greater } else { Ordering::Less };
        }
        let (mut sa, mut sb) = (&a[i..ea], &b[j..eb]);
        if isnum {
            sa = trim_zeros(sa);
            sb = trim_zeros(sb);
            match sa.len().cmp(&sb.len()) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        match sa.cmp(sb) {
            Ordering::Equal => {}
            o => return o,
        }
        i = ea;
        j = eb;
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

fn trim_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|c| **c == b'0').count();
    &s[n..]
}

// ---------------------------------------------------------------------------
// pacman
// ---------------------------------------------------------------------------

/// `[epoch:]pkgver[-pkgrel]`, as `vercmp` (libalpm) compares them.
pub fn pacman(a: &str, b: &str) -> Ordering {
    let (ea, va, ra) = evr(a);
    let (eb, vb, rb) = evr(b);
    alpm_rpmvercmp(ea, eb).then_with(|| alpm_rpmvercmp(va, vb)).then_with(|| match (ra, rb) {
        (Some(x), Some(y)) => alpm_rpmvercmp(x, y),
        _ => Ordering::Equal,
    })
}

/// libalpm's copy of rpmvercmp: no `~`/`^`, the number of separator characters counts, and a
/// trailing alpha segment never beats the end of the string.
fn alpm_rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut one, mut two) = (0usize, 0usize);
    let (mut p1, mut p2) = (0usize, 0usize);
    while one < a.len() && two < b.len() {
        while one < a.len() && !a[one].is_ascii_alphanumeric() {
            one += 1;
        }
        while two < b.len() && !b[two].is_ascii_alphanumeric() {
            two += 1;
        }
        if one >= a.len() || two >= b.len() {
            break;
        }
        if one - p1 != two - p2 {
            return (one - p1).cmp(&(two - p2));
        }
        p1 = one;
        p2 = two;
        let isnum = a[p1].is_ascii_digit();
        let class = |c: &u8| if isnum { c.is_ascii_digit() } else { c.is_ascii_alphabetic() };
        p1 += a[p1..].iter().take_while(|c| class(c)).count();
        p2 += b[p2..].iter().take_while(|c| class(c)).count();
        if p2 == two {
            return if isnum { Ordering::Greater } else { Ordering::Less };
        }
        let (mut sa, mut sb) = (&a[one..p1], &b[two..p2]);
        if isnum {
            sa = trim_zeros(sa);
            sb = trim_zeros(sb);
            match sa.len().cmp(&sb.len()) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        match sa.cmp(sb) {
            Ordering::Equal => {}
            o => return o,
        }
        one = p1;
        two = p2;
    }
    let (ra, rb) = (a.get(one).copied(), b.get(two).copied());
    if ra.is_none() && rb.is_none() {
        return Ordering::Equal;
    }
    if (ra.is_none() && !rb.is_some_and(|c| c.is_ascii_alphabetic())) || ra.is_some_and(|c| c.is_ascii_alphabetic()) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

// ---------------------------------------------------------------------------
// apk
// ---------------------------------------------------------------------------

/// apk-tools token kinds, in their order: at the first difference in kind, the version still
/// on digits is newer than one on a letter, a suffix, a revision or the end; except that a
/// pre-release suffix (`_alpha`, `_beta`, `_pre`, `_rc`) is older than the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ApkKind {
    Digit,
    Letter,
    Suffix,
    Revision,
    End,
}

#[derive(Debug)]
enum ApkTok<'a> {
    /// (digits, first component)
    Digit(&'a str, bool),
    Letter(u8),
    /// The suffix's rank (negative: pre-release) and its number.
    Suffix(i32, u64),
    Revision(u64),
}

impl ApkTok<'_> {
    fn kind(&self) -> ApkKind {
        match self {
            ApkTok::Digit(..) => ApkKind::Digit,
            ApkTok::Letter(_) => ApkKind::Letter,
            ApkTok::Suffix(..) => ApkKind::Suffix,
            ApkTok::Revision(_) => ApkKind::Revision,
        }
    }
}

fn apk_suffix(name: &str) -> i32 {
    match name {
        "alpha" => -4,
        "beta" => -3,
        "pre" => -2,
        "rc" => -1,
        "cvs" => 1,
        "svn" => 2,
        "git" => 3,
        "hg" => 4,
        "p" => 5,
        // Unknown: sorts after the known ones, as an invalid token would compare last.
        _ => 6,
    }
}

fn apk_tokens(v: &str) -> Vec<ApkTok<'_>> {
    let mut out = Vec::new();
    let s = v.trim();
    let b = s.as_bytes();
    let mut i = 0;
    let mut first = true;
    let num = |b: &[u8], i: &mut usize| -> u64 {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        std::str::from_utf8(&b[start..*i]).ok().and_then(|d| d.parse().ok()).unwrap_or(0)
    };
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            out.push(ApkTok::Digit(&s[start..i], first));
            first = false;
        } else if c == b'.' {
            i += 1;
        } else if c.is_ascii_lowercase() && !matches!(out.last(), Some(ApkTok::Letter(_) | ApkTok::Suffix(..) | ApkTok::Revision(_))) {
            out.push(ApkTok::Letter(c));
            i += 1;
        } else if c == b'_' {
            i += 1;
            let start = i;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            let rank = apk_suffix(&s[start..i]);
            out.push(ApkTok::Suffix(rank, num(b, &mut i)));
        } else if c == b'-' && b.get(i + 1) == Some(&b'r') {
            i += 2;
            out.push(ApkTok::Revision(num(b, &mut i)));
        } else {
            // Anything else ends what can be compared.
            break;
        }
    }
    out
}

/// apk-tools' version comparison.
pub fn apk(a: &str, b: &str) -> Ordering {
    let (ta, tb) = (apk_tokens(a), apk_tokens(b));
    let mut k = 0;
    loop {
        match (ta.get(k), tb.get(k)) {
            (None, None) => return Ordering::Equal,
            (Some(x), Some(y)) if x.kind() == y.kind() => {
                let o = match (x, y) {
                    (ApkTok::Digit(p, pf), ApkTok::Digit(q, _)) => {
                        // Later components with a leading zero compare as decimal fractions.
                        if !pf && (p.starts_with('0') || q.starts_with('0')) {
                            p.cmp(q)
                        } else {
                            let (p, q) = (p.trim_start_matches('0'), q.trim_start_matches('0'));
                            p.len().cmp(&q.len()).then_with(|| p.cmp(q))
                        }
                    }
                    (ApkTok::Letter(p), ApkTok::Letter(q)) => p.cmp(q),
                    (ApkTok::Suffix(p, n), ApkTok::Suffix(q, m)) => p.cmp(q).then(n.cmp(m)),
                    (ApkTok::Revision(p), ApkTok::Revision(q)) => p.cmp(q),
                    _ => Ordering::Equal,
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
            (x, y) => {
                if let Some(ApkTok::Suffix(r, _)) = x
                    && *r < 0
                {
                    return Ordering::Less;
                }
                if let Some(ApkTok::Suffix(r, _)) = y
                    && *r < 0
                {
                    return Ordering::Greater;
                }
                let kx = x.map_or(ApkKind::End, ApkTok::kind);
                let ky = y.map_or(ApkKind::End, ApkTok::kind);
                // The earlier kind is the newer version.
                return ky.cmp(&kx);
            }
        }
        k += 1;
    }
}

// ---------------------------------------------------------------------------
// dotted
// ---------------------------------------------------------------------------

/// Numeric components split on `.`, `-`, `_`, `+` and spaces; missing components are 0, so
/// `1.2` equals `1.2.0`. A component with letters compares numerically on its leading digits,
/// then as text (`2a` after `2`).
pub fn dotted(a: &str, b: &str) -> Ordering {
    let parts = |s: &str| -> Vec<String> {
        let s = s.trim();
        let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
        s.split(['.', '-', '_', '+', ' ', ',']).filter(|p| !p.is_empty()).map(str::to_ascii_lowercase).collect()
    };
    let (pa, pb) = (parts(a), parts(b));
    for k in 0..pa.len().max(pb.len()) {
        let x = pa.get(k).map(String::as_str).unwrap_or("0");
        let y = pb.get(k).map(String::as_str).unwrap_or("0");
        let split = |p: &str| -> (u128, String) {
            let d: String = p.chars().take_while(char::is_ascii_digit).collect();
            let rest = p[d.len()..].to_string();
            (d.trim_start_matches('0').parse().unwrap_or(0), rest)
        };
        let (nx, rx) = split(x);
        let (ny, ry) = split(y);
        match nx.cmp(&ny).then_with(|| rx.cmp(&ry)) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    fn check(f: fn(&str, &str) -> Ordering, cases: &[(&str, &str, i32)]) {
        for (a, b, want) in cases {
            let want = want.cmp(&0);
            assert_eq!(f(a, b), want, "{a} vs {b}");
            assert_eq!(f(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn dpkg_vectors() {
        // From dpkg's lib/dpkg/t/t-version.c and Debian policy 5.6.12.
        check(dpkg, &[
            ("0:0-0", "0:0-0", 0),
            ("0:0-0", "0:0", 0),
            ("0:0-0", "0:0-00", 0),
            ("1:0-0", "0:0-0", 1),
            ("0:1-0", "0:0-0", 1),
            ("0:0-1", "0:0-0", 1),
            ("0:0-0", "1:0-0", -1),
            ("0:1-0", "0:1-0", 0),
            ("1.0", "1.0", 0),
            ("1.0-1", "1.0", 1),
            ("1.0~rc1", "1.0", -1),
            ("1.0~rc1-1", "1.0-1", -1),
            ("1.0~~", "1.0~~a", -1),
            ("1.0~~a", "1.0~", -1),
            ("1.0~", "1.0", -1),
            ("1.0", "1.0a", -1),
            ("1.0.1", "1.0a", 1),
            ("1.0.1", "1.0+", 1),
            ("1.0+", "1.0", 1),
            ("2:1.0", "1:9.9", 1),
            ("1.2.3-1ubuntu1", "1.2.3-1", 1),
            ("3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1),
            ("3.0.11-1~deb12u2", "3.0.11-1", -1),
            ("3.0.13-1~deb12u1", "3.0.11-1~deb12u2", 1),
            ("1.18.0-6.1+deb11u3", "1.18.0-6.1", 1),
            ("2.36-9+deb12u4", "2.36-9+deb12u10", -1),
            ("010", "10", 0),
            ("1.001", "1.1", 0),
        ]);
    }

    #[test]
    fn rpm_vectors() {
        // From rpm's tests/rpmvercmp.at.
        check(rpmvercmp, &[
            ("1.0", "1.0", 0),
            ("1.0", "2.0", -1),
            ("2.0.1", "2.0", 1),
            ("2.0.1a", "2.0.1", 1),
            ("5.5p1", "5.5p2", -1),
            ("5.5p10", "5.5p1", 1),
            ("10xyz", "10.1xyz", -1),
            ("xyz10", "xyz10.1", -1),
            ("xyz.4", "xyz.4", 0),
            ("xyz.4", "8", -1),
            ("xyz.4", "2", -1),
            ("5.5p2", "5.6p1", -1),
            ("5.6p1", "6.5p1", -1),
            ("6.0.rc1", "6.0", 1),
            ("10b2", "10a1", 1),
            ("10a2", "10b2", -1),
            ("1.0aa", "1.0a", 1),
            ("10.0001", "10.0001", 0),
            ("10.0001", "10.1", 0),
            ("10.0001", "10.0039", -1),
            ("4.999.9", "5.0", -1),
            ("20101121", "20101122", -1),
            ("2_0", "2_0", 0),
            ("2.0", "2_0", 0),
            ("a", "a", 0),
            ("a+", "a+", 0),
            ("a+", "a_", 0),
            ("+a", "_a", 0),
            ("+_", "_+", 0),
            ("1.0~rc1", "1.0~rc1", 0),
            ("1.0~rc1", "1.0", -1),
            ("1.0~rc1", "1.0~rc2", -1),
            ("1.0~rc1~git123", "1.0~rc1", -1),
            ("1.0^", "1.0", 1),
            ("1.0^git1", "1.0", 1),
            ("1.0^git1", "1.0^git2", -1),
            ("1.0^git1", "1.01", -1),
            ("1.0^20160101", "1.0.1", -1),
            ("1.0^20160101^git1", "1.0^20160101^git1", 0),
            ("1.0^20160102", "1.0^20160101^git1", 1),
            ("1.0~rc1^git1", "1.0~rc1", 1),
            ("1.0^git1~pre", "1.0^git1", -1),
            ("1b.fc17", "1b.fc17", 0),
            ("1b.fc17", "1.fc17", -1),
            ("1g.fc17", "1.fc17", 1),
        ]);
        check(rpm, &[
            ("1:3.0.7-24.el9", "3.0.7-25.el9", 1),
            ("0:3.0.7-24.el9", "3.0.7-24.el9", 0),
            ("3.0.7-24.el9", "3.0.7-27.el9_4", -1),
            ("3.0.7-27.el9_4", "3.0.7-27.el9", 1),
            ("2.9.13-6.el9_4", "2.9.13-6.el9_5.1", -1),
            ("5.14.0-427.el9", "5.14.0-427.13.1.el9_4", -1),
            ("1.2", "1.2-3", 0),
        ]);
    }

    #[test]
    fn pacman_vectors() {
        // From pacman's test/util/vercmptest.sh.
        check(pacman, &[
            ("1.5.0", "1.5.0", 0),
            ("1.5.1", "1.5.0", 1),
            ("1.5.1", "1.5", 1),
            ("1.5.0-1", "1.5.0-1", 0),
            ("1.5.0-1", "1.5.0-2", -1),
            ("1.5.0-1", "1.5.1-1", -1),
            ("1.5.0-2", "1.5.1-1", -1),
            ("1.5-1", "1.5.1-1", -1),
            ("1.5-2", "1.5.1-1", -1),
            ("1.5-2", "1.5.1-2", -1),
            ("1.5", "1.5-1", 0),
            ("1.5-1", "1.5", 0),
            ("1.1-1", "1.1", 0),
            ("1.0-1", "1.1", -1),
            ("1.1-1", "1.0", 1),
            ("1.5b-1", "1.5-1", -1),
            ("1.5b", "1.5", -1),
            ("1.5b-1", "1.5", -1),
            ("1.5b", "1.5.1", -1),
            ("1.0a", "1.0alpha", -1),
            ("1.0alpha", "1.0b", -1),
            ("1.0b", "1.0beta", -1),
            ("1.0beta", "1.0rc", -1),
            ("1.0rc", "1.0", -1),
            ("1.5.a", "1.5", 1),
            ("1.5.b", "1.5.a", 1),
            ("1.5.1", "1.5.b", 1),
            ("1.5.b-1", "1.5.b", 0),
            ("1.5-1", "1.5.b", -1),
            ("2.0", "2_0", 0),
            ("2.0_a", "2_0.a", 0),
            ("2.0a", "2.0.a", -1),
            ("2___a", "2_a", 1),
            ("0:1.0", "0:1.0", 0),
            ("0:1.0", "0:1.1", -1),
            ("1:1.0", "0:1.0", 1),
            ("1:1.0", "0:1.1", 1),
            ("1:1.0", "2:1.1", -1),
            ("1:1.0", "0:1.0-1", 1),
            ("1:1.0-1", "0:1.1-1", 1),
            ("0:1.0", "1.0", 0),
            ("0:1.0", "1.1", -1),
            ("0:1.1", "1.0", 1),
            ("1:1.0", "1.0", 1),
            ("1:1.0", "1.1", 1),
            ("1:1.1", "1.1", 1),
        ]);
    }

    #[test]
    fn apk_vectors() {
        // From apk-tools' test/version.data.
        check(apk, &[
            ("2.34", "0.1.0_alpha", 1),
            ("0.1.0_alpha", "0.1.0_alpha", 0),
            ("0.1.0_alpha", "0.1.3_alpha", -1),
            ("0.1.0_alpha2", "0.1.0_alpha", 1),
            ("0.1.0_alpha", "2.2.39-r1", -1),
            ("2.2.39-r1", "1.0.4-r3", 1),
            ("1.0.4-r3", "1.0.4-r4", -1),
            ("1.0.4-r4", "1.6", -1),
            ("1.6", "1.0.2", 1),
            ("1.0.2", "0.7-r1", 1),
            ("0.7-r1", "1.0.0", -1),
            ("1.0.0", "1.0.1", -1),
            ("1.0.1", "1.1", -1),
            ("1.1", "1.1_alpha1", 1),
            ("1.1_alpha1", "1.2.1", -1),
            ("1.2.1", "1.2", 1),
            ("1.2", "1.3_alpha", -1),
            ("1.3_alpha", "1.3_alpha2", -1),
            ("1.3_alpha2", "1.3_alpha3", -1),
            ("1.3_alpha8", "0.6.0", 1),
            ("0.7.0", "0.8_beta1", -1),
            ("0.8_beta1", "0.8_beta2", -1),
            ("0.8_beta4", "4.8-r1", -1),
            ("3.10.18-r1", "2.3.0b-r1", 1),
            ("2.3.0b-r1", "2.3.0b-r2", -1),
            ("2.3.0b-r3", "1.0.2a", 1),
            ("1.0.2a", "1.0.1", 1),
            ("1.0_rc1", "1.0", -1),
            ("1.0_p1", "1.0", 1),
            ("1.0a", "1.0", 1),
            ("1.0_rc1", "1.0_beta9", 1),
            ("3.1.4-r0", "3.1.4-r1", -1),
            ("3.3.2-r0", "3.3.1-r5", 1),
            ("1.01", "1.1", -1),
        ]);
    }

    #[test]
    fn dotted_versions() {
        check(dotted, &[
            ("120.0.6099.130", "120.0.6099.129", 1),
            ("120.0.6099.130", "121.0", -1),
            ("1.2", "1.2.0", 0),
            ("1.2", "1.2.0.1", -1),
            ("23.01", "23.1", 0),
            ("24.07", "23.01", 1),
            ("v1.10", "1.9", 1),
            ("2.4.1-beta", "2.4.1", 1),
            ("10.0.19045.3803", "10.0.19045.3803", 0),
        ]);
    }

    #[test]
    fn ranges() {
        let r = |i: Option<&str>, f: Option<&str>, l: Option<&str>| Range {
            introduced: i.map(Into::into),
            introduced_exclusive: false,
            fixed: f.map(Into::into),
            last_affected: l.map(Into::into),
        };
        let s = Scheme::Dpkg;
        assert!(r(Some("0"), Some("3.0.11-1~deb12u2"), None).contains(s, "3.0.11-1~deb12u1"));
        assert!(!r(Some("0"), Some("3.0.11-1~deb12u2"), None).contains(s, "3.0.11-1~deb12u2"), "the fixed version is not affected");
        assert!(r(None, None, None).contains(s, "1.0"), "no fix: everything");
        assert!(!r(Some("2.0"), None, None).contains(s, "1.9"));
        assert!(r(None, None, Some("2.0")).contains(s, "2.0"));
        assert!(!r(None, None, Some("2.0")).contains(s, "2.0.1"));
        let excl = Range { introduced: Some("1.0".into()), introduced_exclusive: true, fixed: Some("2.0".into()), last_affected: None };
        assert!(!excl.contains(Scheme::Dotted, "1.0") && excl.contains(Scheme::Dotted, "1.0.1"));
        assert_eq!(Scheme::Rpm.cmp("1:1", "2"), Greater);
        assert_eq!(Scheme::Pacman.cmp("1.0", "1.0"), Equal);
        assert_eq!(Scheme::Apk.cmp("1.0", "1.1"), Less);
    }
}
