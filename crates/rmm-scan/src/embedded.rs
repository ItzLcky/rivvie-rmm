//! Content hidden inside other formats: the target and arguments of a shortcut (LNK), script
//! blocks in HTML and HTA files, and JavaScript or embedded files in PDF streams. Each comes
//! out as a part of its own so rules see the decoded text.

use crate::container::{Budget, Member};
use crate::filetype::memfind;

fn u16le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// A shortcut's strings as text: `target:`, `arguments:`, `working_dir:`, `icon:` lines
/// ([MS-SHLLINK]). Rules about suspicious shortcuts match on this.
pub fn lnk(d: &[u8]) -> Option<String> {
    let flags = u32le(d, 0x14)?;
    let mut i = 0x4cusize;
    if flags & 0x1 != 0 {
        i = i.checked_add(2 + u16le(d, i)? as usize)?;
    }
    let mut out = String::new();
    if flags & 0x2 != 0 {
        let size = u32le(d, i)? as usize;
        if let Some(info) = d.get(i..i.saturating_add(size))
            && let Some(base) = u32le(info, 0x10).map(|o| o as usize)
            && let Some(rest) = info.get(base..)
        {
            let n = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
            out.push_str(&format!("target: {}\n", String::from_utf8_lossy(rest.get(..n).unwrap_or_default())));
        }
        i = i.checked_add(size)?;
    }
    let unicode = flags & 0x80 != 0;
    for (bit, label) in [(0x4, "name"), (0x8, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"), (0x40, "icon")] {
        if flags & bit == 0 {
            continue;
        }
        let count = u16le(d, i)? as usize;
        i += 2;
        let bytes = if unicode { count * 2 } else { count };
        let raw = d.get(i..i.saturating_add(bytes).min(d.len())).unwrap_or_default();
        let s = if unicode {
            String::from_utf16_lossy(&raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<_>>())
        } else {
            String::from_utf8_lossy(raw).into_owned()
        };
        out.push_str(&format!("{label}: {s}\n"));
        i = i.saturating_add(bytes);
    }
    Some(out)
}

fn find_nocase(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let h = hay.get(from..)?;
    h.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle)).map(|p| p + from)
}

/// The bodies of `<script>` elements (HTML, HTA, SVG).
pub fn html_scripts(d: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < 100 {
        let Some(open) = find_nocase(d, b"<script", i) else { break };
        let Some(gt) = d.get(open..).and_then(|r| r.iter().position(|b| *b == b'>')).map(|p| p + open + 1) else { break };
        let close = find_nocase(d, b"</script", gt).unwrap_or(d.len());
        let body = d.get(gt..close).unwrap_or_default();
        if body.iter().any(|b| !b.is_ascii_whitespace()) {
            out.push(body.to_vec());
        }
        i = close.max(gt);
    }
    out
}

/// PDF streams worth scanning: JavaScript, embedded files, and anything that unpacks to text
/// or a known type. Flate-compressed streams are inflated within the budget.
pub fn pdf_parts(d: &[u8], budget: &mut Budget) -> Vec<Member> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut n = 0;
    while n < 500 && !budget.stopped() {
        let Some(s) = d.get(i..).and_then(|r| memfind(r, b"stream")).map(|p| p + i) else { break };
        n += 1;
        let dict_from = s.saturating_sub(512);
        let dict = d.get(dict_from..s).unwrap_or_default();
        let dict = dict.get(dict.windows(2).rposition(|w| w == b"<<").unwrap_or(0)..).unwrap_or_default();
        let mut body_start = s + 6;
        if d.get(body_start) == Some(&b'\r') {
            body_start += 1;
        }
        if d.get(body_start) == Some(&b'\n') {
            body_start += 1;
        }
        let end = d.get(body_start..).and_then(|r| memfind(r, b"endstream")).map_or(d.len(), |p| p + body_start);
        i = end.max(s + 6);
        // "endstream" also contains "stream": skip past it.
        if d.get(s.saturating_sub(3)..s) == Some(b"end") {
            continue;
        }
        let raw = d.get(body_start..end).unwrap_or_default();
        let flate = memfind(dict, b"/FlateDecode").is_some();
        let interesting = memfind(dict, b"/JS").is_some() || memfind(dict, b"/JavaScript").is_some() || memfind(dict, b"/EmbeddedFile").is_some();
        if !budget.entry() {
            break;
        }
        let data = if flate {
            match crate::container::zlib(raw, budget) {
                Some(v) => v,
                None => continue,
            }
        } else {
            raw.to_vec()
        };
        let kind = crate::filetype::identify(&data);
        if interesting || kind != crate::filetype::FileType::Unknown {
            out.push(Member { name: format!("pdf-stream[{n}]"), data });
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A shortcut to `target` with `args`, Unicode strings.
    pub fn make_lnk(target: &str, args: &str) -> Vec<u8> {
        let mut d = vec![0u8; 0x4c];
        d[..20].copy_from_slice(&[0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
        d[0x14..0x18].copy_from_slice(&(0x2u32 | 0x20 | 0x80).to_le_bytes());
        let mut info = vec![0u8; 0x1c];
        info[0x10..0x14].copy_from_slice(&0x1cu32.to_le_bytes());
        info.extend_from_slice(target.as_bytes());
        info.push(0);
        let len = info.len() as u32;
        info[..4].copy_from_slice(&len.to_le_bytes());
        d.extend_from_slice(&info);
        let a: Vec<u16> = args.encode_utf16().collect();
        d.extend_from_slice(&(a.len() as u16).to_le_bytes());
        d.extend(a.iter().flat_map(|c| c.to_le_bytes()));
        d
    }

    #[test]
    fn shortcut_strings() {
        let s = lnk(&make_lnk("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-w hidden -enc SQBFAFgA")).unwrap();
        assert_eq!(s, "target: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\narguments: -w hidden -enc SQBFAFgA\n");
    }

    #[test]
    fn scripts_in_html_and_pdf() {
        let h = html_scripts(b"<html><SCRIPT language=vbscript>CreateObject(\"WScript.Shell\").Run \"calc\"</script><script src=x></script></html>");
        assert_eq!(h, [b"CreateObject(\"WScript.Shell\").Run \"calc\"".to_vec()]);
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"app.alert('x'); eval(unescape('%61'));").unwrap();
        let mut pdf = b"%PDF-1.4\n1 0 obj << /S /JavaScript /Filter /FlateDecode >>\nstream\n".to_vec();
        pdf.extend(e.finish().unwrap());
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        let mut b = Budget::new(crate::Limits::default());
        let parts = pdf_parts(&pdf, &mut b);
        assert_eq!(parts.len(), 1);
        assert!(memfind(&parts[0].data, b"eval(unescape").is_some());
    }

    #[test]
    fn hostile_input_never_panics() {
        let l = make_lnk("C:\\x.exe", "args");
        crate::fuzz::mutate(&[&l], 5000, |d| {
            let _ = lnk(d);
        });
        let pdf = b"%PDF-1.4\n<< /JS /FlateDecode >>\nstream\r\nx\x9c\x03\0\0\0\0\x01\nendstream <script>x</script>".to_vec();
        crate::fuzz::mutate(&[&pdf], 3000, |d| {
            let _ = html_scripts(d);
            let mut b = Budget::new(crate::Limits { max_unpacked: 1 << 20, ..crate::Limits::default() });
            let _ = pdf_parts(d, &mut b);
        });
    }
}
