//! A small PDF writer for invoices and quarterly business reviews: A4 pages, the standard
//! Helvetica fonts (so nothing is embedded), text, lines and filled boxes. Text is encoded as
//! Windows-1252; characters outside it print as `?`.

use std::fmt::Write as _;

pub const PAGE_W: f32 = 595.0;
pub const PAGE_H: f32 = 842.0;
pub const MARGIN: f32 = 50.0;

/// Helvetica and Helvetica-Bold advance widths (1/1000 em) for ASCII 32..=126, from the AFMs.
const HELV: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278,
    278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722,
    667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556,
    556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];
const HELV_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333,
    333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722,
    667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611,
    611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

/// Windows-1252 for a character, if it has one.
fn cp1252(c: char) -> Option<u8> {
    let u = c as u32;
    if (0x20..0x7f).contains(&u) || (0xa0..=0xff).contains(&u) {
        return Some(u as u8);
    }
    Some(match c {
        '€' => 0x80,
        '‚' => 0x82,
        '„' => 0x84,
        '…' => 0x85,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        '™' => 0x99,
        _ => return None,
    })
}

/// Width of `s` in points.
pub fn width(s: &str, size: f32, bold: bool) -> f32 {
    let table = if bold { &HELV_BOLD } else { &HELV };
    let units: u32 = s
        .chars()
        .map(|c| {
            let u = c as u32;
            if (32..=126).contains(&u) { table[(u - 32) as usize] as u32 } else { 556 }
        })
        .sum();
    units as f32 * size / 1000.0
}

/// Breaks `s` into lines no wider than `max` points (hard line breaks are kept).
pub fn wrap(s: &str, size: f32, bold: bool, max: f32) -> Vec<String> {
    let mut out = vec![];
    for para in s.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            let candidate = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
            if width(&candidate, size, bold) <= max || line.is_empty() {
                line = candidate;
                // A single word wider than the line: cut it.
                while width(&line, size, bold) > max && line.chars().count() > 1 {
                    let mut head = String::new();
                    for ch in line.chars() {
                        if width(&format!("{head}{ch}"), size, bold) > max {
                            break;
                        }
                        head.push(ch);
                    }
                    let rest: String = line.chars().skip(head.chars().count().max(1)).collect();
                    out.push(head);
                    line = rest;
                }
            } else {
                out.push(std::mem::take(&mut line));
                line = word.to_string();
            }
        }
        out.push(line);
    }
    out
}

fn escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let b = cp1252(c).unwrap_or(b'?');
        match b {
            b'(' | b')' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7e => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{b:03o}");
            }
        }
    }
    out
}

/// An image XObject: JPEG bytes as they are (`dct`), or Flate-compressed 8-bit RGB (or grey)
/// samples with an optional Flate-compressed 8-bit alpha channel as a soft mask.
/// [`crate::branding::pdf_image`] makes one from an uploaded logo.
#[derive(Debug, Clone)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
    pub dct: bool,
    pub gray: bool,
    pub smask: Option<Vec<u8>>,
}

impl Image {
    /// The size that fits in `max_w` by `max_h` points, keeping the aspect ratio.
    pub fn fit(&self, max_w: f32, max_h: f32) -> (f32, f32) {
        let (w, h) = (self.width.max(1) as f32, self.height.max(1) as f32);
        let k = (max_w / w).min(max_h / h);
        (w * k, h * k)
    }
}

/// A document under construction. Coordinates are points from the top-left corner.
#[derive(Default)]
pub struct Doc {
    pages: Vec<String>,
    cur: String,
    images: Vec<Image>,
}

impl Doc {
    pub fn new() -> Self {
        Doc::default()
    }

    pub fn new_page(&mut self) {
        if !self.cur.is_empty() {
            self.pages.push(std::mem::take(&mut self.cur));
        }
    }

    /// Text with its baseline at `y` from the top.
    pub fn text(&mut self, x: f32, y: f32, size: f32, bold: bool, gray: f32, s: &str) {
        let _ = writeln!(
            self.cur,
            "BT {gray:.2} g /{} {size:.1} Tf {x:.2} {:.2} Td ({}) Tj ET",
            if bold { "F2" } else { "F1" },
            PAGE_H - y,
            escape(s)
        );
    }

    /// Text ending at `right`.
    pub fn text_right(&mut self, right: f32, y: f32, size: f32, bold: bool, gray: f32, s: &str) {
        let w = width(s, size, bold);
        self.text(right - w, y, size, bold, gray, s);
    }

    pub fn line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, w: f32, gray: f32) {
        let _ = writeln!(self.cur, "{gray:.2} G {w:.2} w {x1:.2} {:.2} m {x2:.2} {:.2} l S", PAGE_H - y1, PAGE_H - y2);
    }

    /// A filled box whose top-left corner is at (`x`, `y`).
    pub fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, gray: f32) {
        let _ = writeln!(self.cur, "{gray:.2} g {x:.2} {:.2} {w:.2} {h:.2} re f", PAGE_H - y - h);
    }

    /// A filled box in an RGB colour (0-1 each).
    pub fn rect_rgb(&mut self, x: f32, y: f32, w: f32, h: f32, rgb: (f32, f32, f32)) {
        let _ = writeln!(self.cur, "{:.3} {:.3} {:.3} rg {x:.2} {:.2} {w:.2} {h:.2} re f", rgb.0, rgb.1, rgb.2, PAGE_H - y - h);
    }

    /// Adds an image to the document; draw it with [`Doc::image`].
    pub fn add_image(&mut self, img: Image) -> usize {
        self.images.push(img);
        self.images.len() - 1
    }

    /// Draws an added image with its top-left corner at (`x`, `y`), `w` by `h` points.
    pub fn image(&mut self, idx: usize, x: f32, y: f32, w: f32, h: f32) {
        let _ = writeln!(self.cur, "q {w:.2} 0 0 {h:.2} {x:.2} {:.2} cm /Im{idx} Do Q", PAGE_H - y - h);
    }

    /// The finished file.
    pub fn finish(mut self, title: &str) -> Vec<u8> {
        self.new_page();
        if self.pages.is_empty() {
            self.pages.push(String::new());
        }
        let n = self.pages.len();
        // Objects: 1 catalog, 2 pages, 3 F1, 4 F2, 5 info, then (page, content) pairs, then
        // each image followed by its soft mask, if it has one.
        let mut image_ids = vec![];
        let mut next = 6 + n * 2;
        for img in &self.images {
            image_ids.push(next);
            next += if img.smask.is_some() { 2 } else { 1 };
        }
        let xobjects = if self.images.is_empty() {
            String::new()
        } else {
            let refs: Vec<String> = image_ids.iter().enumerate().map(|(i, id)| format!("/Im{i} {id} 0 R")).collect();
            format!(" /XObject << {} >>", refs.join(" "))
        };
        let mut objs: Vec<Vec<u8>> = vec![];
        objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
        let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 6 + i * 2)).collect();
        objs.push(format!("<< /Type /Pages /Count {n} /Kids [{}] >>", kids.join(" ")).into_bytes());
        objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".to_vec());
        objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>".to_vec());
        objs.push(format!("<< /Title ({}) /Producer (rmm-server) >>", escape(title)).into_bytes());
        for (i, content) in self.pages.iter().enumerate() {
            objs.push(
                format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >>{xobjects} >> /Contents {} 0 R >>",
                    7 + i * 2
                )
                .into_bytes(),
            );
            let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
            stream.extend_from_slice(content.as_bytes());
            stream.extend_from_slice(b"\nendstream");
            objs.push(stream);
        }
        for (img, id) in self.images.iter().zip(&image_ids) {
            let stream = |dict: String, data: &[u8]| {
                let mut s = format!("{dict} /Length {} >>\nstream\n", data.len()).into_bytes();
                s.extend_from_slice(data);
                s.extend_from_slice(b"\nendstream");
                s
            };
            let colour = if img.gray { "/DeviceGray" } else { "/DeviceRGB" };
            let filter = if img.dct { "/DCTDecode" } else { "/FlateDecode" };
            let smask = if img.smask.is_some() { format!(" /SMask {} 0 R", id + 1) } else { String::new() };
            let dict = format!(
                "<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace {colour} /BitsPerComponent 8 /Filter {filter}{smask}",
                img.width, img.height
            );
            objs.push(stream(dict, &img.data));
            if let Some(mask) = &img.smask {
                let dict = format!(
                    "<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode",
                    img.width, img.height
                );
                objs.push(stream(dict, mask));
            }
        }
        let mut out = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
        let mut offsets = vec![];
        for (i, o) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        let mut x = format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1);
        for off in offsets {
            let _ = writeln!(x, "{off:010} 00000 n ");
        }
        let _ = write!(x, "trailer\n<< /Size {} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1);
        out.extend_from_slice(x.as_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// Invoices
// ---------------------------------------------------------------------------

pub struct InvoiceLine {
    pub description: String,
    pub quantity: String,
    pub unit_price: String,
    pub amount: String,
}

pub struct Invoice {
    pub title: String,
    pub number: String,
    pub company: String,
    pub company_address: String,
    pub bill_to: String,
    pub issue_date: String,
    pub due_date: String,
    pub period: Option<String>,
    pub lines: Vec<InvoiceLine>,
    pub total: String,
    pub notes: String,
    pub footer: String,
    /// Shown across the top (VOID, a credit note's reference).
    pub banner: Option<String>,
    /// The branding logo, above the company name.
    pub logo: Option<Image>,
}

pub fn invoice(inv: &Invoice) -> Vec<u8> {
    let mut d = Doc::new();
    let right = PAGE_W - MARGIN;
    let col_qty = right - 210.0;
    let col_unit = right - 100.0;
    let logo = inv.logo.clone().map(|img| {
        let size = img.fit(160.0, 40.0);
        (d.add_image(img), size)
    });
    let header = |d: &mut Doc| -> f32 {
        if let Some((idx, (w, h))) = logo {
            d.image(idx, MARGIN, 14.0 + (40.0 - h), w, h);
        }
        d.text(MARGIN, 70.0, 16.0, true, 0.1, &inv.company);
        let mut y = 86.0;
        for l in inv.company_address.lines().filter(|l| !l.trim().is_empty()) {
            d.text(MARGIN, y, 9.0, false, 0.35, l.trim());
            y += 12.0;
        }
        d.text_right(right, 70.0, 20.0, true, 0.1, &inv.title);
        d.text_right(right, 88.0, 10.0, false, 0.35, &inv.number);
        y.max(110.0)
    };
    let table_head = |d: &mut Doc, y: f32| -> f32 {
        d.rect(MARGIN, y, right - MARGIN, 20.0, 0.93);
        d.text(MARGIN + 6.0, y + 14.0, 9.0, true, 0.2, "Description");
        d.text_right(col_qty, y + 14.0, 9.0, true, 0.2, "Qty");
        d.text_right(col_unit, y + 14.0, 9.0, true, 0.2, "Unit price");
        d.text_right(right - 6.0, y + 14.0, 9.0, true, 0.2, "Amount");
        y + 28.0
    };
    let mut y = header(&mut d);
    if let Some(b) = &inv.banner {
        d.text_right(right, 104.0, 11.0, true, 0.45, b);
    }
    y += 16.0;
    d.text(MARGIN, y, 8.0, true, 0.45, "BILL TO");
    d.text(330.0, y, 8.0, true, 0.45, "DETAILS");
    y += 14.0;
    let mut by = y;
    for l in inv.bill_to.lines().filter(|l| !l.trim().is_empty()) {
        for w in wrap(l.trim(), 10.0, false, 250.0) {
            d.text(MARGIN, by, 10.0, by == y, 0.1, &w);
            by += 13.0;
        }
    }
    let mut dy = y;
    let mut detail = |d: &mut Doc, k: &str, v: &str| {
        d.text(330.0, dy, 9.0, false, 0.4, k);
        d.text_right(right, dy, 9.0, false, 0.1, v);
        dy += 13.0;
    };
    detail(&mut d, "Issued", &inv.issue_date);
    detail(&mut d, "Due", &inv.due_date);
    if let Some(p) = &inv.period {
        detail(&mut d, "Period", p);
    }
    y = by.max(dy) + 18.0;
    y = table_head(&mut d, y);
    for l in &inv.lines {
        let rows = wrap(&l.description, 9.5, false, col_qty - MARGIN - 60.0);
        let h = rows.len() as f32 * 12.0 + 6.0;
        if y + h > PAGE_H - 110.0 {
            d.text_right(right, PAGE_H - 40.0, 8.0, false, 0.5, "Continued on the next page");
            d.new_page();
            y = header(&mut d) + 20.0;
            y = table_head(&mut d, y);
        }
        for (i, r) in rows.iter().enumerate() {
            d.text(MARGIN + 6.0, y + i as f32 * 12.0, 9.5, false, 0.1, r);
        }
        d.text_right(col_qty, y, 9.5, false, 0.1, &l.quantity);
        d.text_right(col_unit, y, 9.5, false, 0.1, &l.unit_price);
        d.text_right(right - 6.0, y, 9.5, false, 0.1, &l.amount);
        y += h;
        d.line(MARGIN, y - 8.0, right, y - 8.0, 0.4, 0.88);
    }
    if y > PAGE_H - 150.0 {
        d.new_page();
        y = header(&mut d) + 20.0;
    }
    y += 8.0;
    d.text(col_unit - 70.0, y, 11.0, true, 0.1, "Total");
    d.text_right(right - 6.0, y, 11.0, true, 0.1, &inv.total);
    y += 30.0;
    for l in wrap(&inv.notes, 9.0, false, right - MARGIN) {
        if y > PAGE_H - 60.0 {
            break;
        }
        d.text(MARGIN, y, 9.0, false, 0.3, &l);
        y += 12.0;
    }
    let mut fy = PAGE_H - 50.0;
    for l in wrap(&inv.footer, 8.0, false, right - MARGIN).iter().rev() {
        d.text(MARGIN, fy, 8.0, false, 0.5, l);
        fy -= 10.0;
    }
    d.finish(&format!("{} {}", inv.title, inv.number))
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// A simple report: a title, then sections of key figures, tables and bar charts.
pub enum Block {
    Heading(String),
    Paragraph(String),
    /// (label, value) pairs in two columns.
    Figures(Vec<(String, String)>),
    /// Header row, then rows; the first column is left-aligned, the rest right-aligned.
    Table(Vec<String>, Vec<Vec<String>>),
    /// Labelled horizontal bars (value, shown text).
    Bars(Vec<(String, f64, String)>),
}

// Kept for callers without a logo (scheduled reports are built in parallel to this).
#[allow(dead_code)]
pub fn report(title: &str, subtitle: &str, company: &str, blocks: &[Block]) -> Vec<u8> {
    report_with_logo(title, subtitle, company, None, blocks)
}

/// [`report`] with the branding logo at the top right of every page.
pub fn report_with_logo(title: &str, subtitle: &str, company: &str, logo: Option<Image>, blocks: &[Block]) -> Vec<u8> {
    let mut d = Doc::new();
    let right = PAGE_W - MARGIN;
    let logo = logo.map(|img| {
        let size = img.fit(140.0, 30.0);
        (d.add_image(img), size)
    });
    let top = |d: &mut Doc| {
        d.rect_rgb(0.0, 0.0, PAGE_W, 8.0, (0.11, 0.17, 0.33));
        d.text(MARGIN, 40.0, 8.0, true, 0.45, &company.to_uppercase());
        if let Some((idx, (w, h))) = logo {
            d.image(idx, right - w, 16.0 + (30.0 - h), w, h);
        }
        64.0
    };
    let mut y = top(&mut d);
    d.text(MARGIN, y + 14.0, 20.0, true, 0.1, title);
    d.text(MARGIN, y + 32.0, 10.0, false, 0.4, subtitle);
    y += 56.0;
    let room = |d: &mut Doc, y: &mut f32, need: f32| {
        if *y + need > PAGE_H - MARGIN {
            d.new_page();
            *y = top(d) + 10.0;
        }
    };
    for b in blocks {
        match b {
            Block::Heading(h) => {
                room(&mut d, &mut y, 60.0);
                y += 14.0;
                d.text(MARGIN, y, 12.0, true, 0.1, h);
                d.line(MARGIN, y + 6.0, right, y + 6.0, 0.6, 0.8);
                y += 22.0;
            }
            Block::Paragraph(p) => {
                for l in wrap(p, 9.5, false, right - MARGIN) {
                    room(&mut d, &mut y, 13.0);
                    d.text(MARGIN, y, 9.5, false, 0.25, &l);
                    y += 13.0;
                }
                y += 6.0;
            }
            Block::Figures(f) => {
                let col = (right - MARGIN) / 3.0;
                for chunk in f.chunks(3) {
                    room(&mut d, &mut y, 40.0);
                    for (i, (k, v)) in chunk.iter().enumerate() {
                        let x = MARGIN + i as f32 * col;
                        d.text(x, y + 14.0, 16.0, true, 0.1, v);
                        d.text(x, y + 28.0, 8.5, false, 0.45, k);
                    }
                    y += 42.0;
                }
            }
            Block::Table(head, rows) => {
                let n = head.len().max(1);
                let first = (right - MARGIN) * if n > 1 { 0.4 } else { 1.0 };
                let rest = if n > 1 { (right - MARGIN - first) / (n - 1) as f32 } else { 0.0 };
                let row = |d: &mut Doc, y: f32, cells: &[String], bold: bool| {
                    for (i, c) in cells.iter().enumerate() {
                        if i == 0 {
                            let t = wrap(c, 9.0, bold, first - 8.0).into_iter().next().unwrap_or_default();
                            d.text(MARGIN + 4.0, y, 9.0, bold, 0.15, &t);
                        } else {
                            d.text_right(MARGIN + first + rest * i as f32 - 4.0, y, 9.0, bold, 0.15, c);
                        }
                    }
                };
                room(&mut d, &mut y, 40.0);
                d.rect(MARGIN, y - 11.0, right - MARGIN, 16.0, 0.93);
                row(&mut d, y, head, true);
                y += 17.0;
                for r in rows {
                    room(&mut d, &mut y, 15.0);
                    row(&mut d, y, r, false);
                    y += 14.0;
                }
                y += 8.0;
            }
            Block::Bars(bars) => {
                let max = bars.iter().map(|b| b.1).fold(0.0_f64, f64::max).max(1e-9);
                let label_w = 140.0;
                let bar_w = right - MARGIN - label_w - 60.0;
                for (label, v, shown) in bars {
                    room(&mut d, &mut y, 16.0);
                    let t = wrap(label, 9.0, false, label_w - 8.0).into_iter().next().unwrap_or_default();
                    d.text(MARGIN, y, 9.0, false, 0.25, &t);
                    let w = (*v / max) as f32 * bar_w;
                    d.rect_rgb(MARGIN + label_w, y - 8.0, w.max(1.0), 10.0, (0.23, 0.42, 0.85));
                    d.text(MARGIN + label_w + w + 6.0, y, 8.5, false, 0.3, shown);
                    y += 15.0;
                }
                y += 8.0;
            }
        }
    }
    d.finish(title)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_and_wraps() {
        assert!((width("Hello", 10.0, false) - 22.78).abs() < 0.01);
        assert!(width("W", 10.0, true) > width("i", 10.0, true));
        let lines = wrap("one two three four five six seven", 10.0, false, 60.0);
        assert!(lines.len() > 1 && lines.iter().all(|l| width(l, 10.0, false) <= 60.0), "{lines:?}");
        assert_eq!(wrap("a\nb", 10.0, false, 100.0), vec!["a", "b"]);
        let long = wrap("Supercalifragilisticexpialidocious", 10.0, false, 40.0);
        assert!(long.len() > 1 && long.iter().all(|l| width(l, 10.0, false) <= 40.0), "{long:?}");
    }

    #[test]
    fn escapes_text() {
        assert_eq!(escape("a(b)c\\"), "a\\(b\\)c\\\\");
        assert_eq!(escape("€5 – ok"), "\\2005 \\226 ok");
        assert_eq!(escape("日本"), "??");
    }

    #[test]
    fn writes_a_valid_file() {
        let inv = Invoice {
            title: "Invoice".into(),
            number: "INV-1001".into(),
            company: "Acme IT".into(),
            company_address: "1 Main St\nSpringfield".into(),
            bill_to: "Client A\n2 Side Rd".into(),
            issue_date: "2026-11-12".into(),
            due_date: "2026-12-12".into(),
            period: Some("1 Nov 2026 – 30 Nov 2026".into()),
            lines: (0..80)
                .map(|i| InvoiceLine { description: format!("Line {i}"), quantity: "1".into(), unit_price: "USD 1.00".into(), amount: "USD 1.00".into() })
                .collect(),
            total: "USD 80.00".into(),
            notes: "Thanks".into(),
            footer: "Pay by bank transfer".into(),
            banner: None,
            logo: None,
        };
        let pdf = invoice(&inv);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.starts_with("%PDF-1.4") && text.trim_end().ends_with("%%EOF"));
        assert!(!text.contains("/Count 1 "), "80 lines take more than one page");
        assert_eq!(text.matches("/Type /Page ").count(), text.split("/Count ").nth(1).unwrap().split_whitespace().next().unwrap().parse::<usize>().unwrap());
        // The xref offsets point at the objects.
        let xref_at: usize = text.rsplit("startxref\n").next().unwrap().lines().next().unwrap().parse().unwrap();
        assert!(pdf[xref_at..].starts_with(b"xref"));
        let tail = String::from_utf8_lossy(&pdf[xref_at..]).to_string();
        let first = tail.lines().nth(3).unwrap()[..10].parse::<usize>().unwrap();
        assert!(pdf[first..].starts_with(b"1 0 obj"));
        let r = report("QBR", "Q4 2026", "Acme", &[Block::Heading("Tickets".into()), Block::Bars(vec![("Oct".into(), 3.0, "3".into())])]);
        assert!(String::from_utf8_lossy(&r).contains("/Count 1"));
        assert!(!String::from_utf8_lossy(&r).contains("/XObject"));
    }

    #[test]
    fn embeds_a_logo() {
        let logo = crate::branding::pdf_image(&crate::branding::tests::sample_png(40, 10)).unwrap();
        let blocks: Vec<Block> = (0..120).map(|i| Block::Paragraph(format!("Paragraph {i}"))).collect();
        let pdf = report_with_logo("QBR", "Q4", "Acme", Some(logo), &blocks);
        let text = String::from_utf8_lossy(&pdf);
        let pages = text.matches("/Type /Page ").count();
        assert!(pages > 1);
        assert_eq!(text.matches("/XObject << /Im0 ").count(), pages, "every page can draw it");
        assert_eq!(text.matches("/Im0 Do").count(), pages, "and does, in the header");
        assert_eq!(text.matches("/Subtype /Image").count(), 2, "the image and its soft mask, once");
        let id: usize = text.split("/XObject << /Im0 ").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
        assert!(text.contains(&format!("{id} 0 obj\n<< /Type /XObject /Subtype /Image /Width 40 /Height 10 /ColorSpace /DeviceRGB")));
        assert!(text.contains(&format!("/SMask {} 0 R", id + 1)));
        // The xref still points at every object.
        let xref_at: usize = text.rsplit("startxref\n").next().unwrap().lines().next().unwrap().parse().unwrap();
        let tail = String::from_utf8_lossy(&pdf[xref_at..]).to_string();
        for (i, line) in tail.lines().skip(3).take_while(|l| l.ends_with(" n ")).enumerate() {
            let off: usize = line[..10].parse().unwrap();
            assert!(pdf[off..].starts_with(format!("{} 0 obj", i + 1).as_bytes()), "object {}", i + 1);
        }
    }
}
