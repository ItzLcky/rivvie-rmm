//! Turns captured screens into the rectangles that changed, JPEG-encoded.
//!
//! The picture is compared with the previous one in 64x64 tiles. Each 64-pixel band of rows
//! becomes one rectangle per run of adjacent changed tiles, so a typing cursor costs one
//! small JPEG while a scrolled window costs a few wide ones.

use rmm_proto::desktop::{Codec, Rect};

const TILE: usize = 64;

/// A captured screen: 32-bit BGRX pixels, rows packed (`width * 4` bytes each).
pub struct Image<'a> {
    pub data: &'a [u8],
    pub width: usize,
    pub height: usize,
}

pub struct Encoder {
    quality: u8,
    scale: usize,
    prev: Vec<u8>,
    width: usize,
    height: usize,
    scaled: Vec<u8>,
    /// The next frame must cover everything (new session, new settings, new size).
    full: bool,
}

impl Encoder {
    pub fn new(quality: u8, scale: u32) -> Self {
        Encoder { quality, scale: scale.clamp(1, 4) as usize, prev: vec![], width: 0, height: 0, scaled: vec![], full: true }
    }

    /// Size of the encoded picture for a screen of `w` x `h`.
    pub fn output_size(&self, w: usize, h: usize) -> (usize, usize) {
        ((w / self.scale).max(1), (h / self.scale).max(1))
    }

    /// Changed areas since the previous call, in output pixels.
    pub fn encode(&mut self, img: &Image) -> Vec<Rect> {
        let (w, h) = self.output_size(img.width, img.height);
        let mut cur = std::mem::take(&mut self.scaled);
        if self.scale == 1 {
            cur.clear();
            cur.extend_from_slice(&img.data[..w * h * 4]);
        } else {
            downscale(img, self.scale, &mut cur);
        }
        if self.full || w != self.width || h != self.height || self.prev.len() != cur.len() {
            self.full = false;
            self.width = w;
            self.height = h;
            self.prev.clear();
            self.prev.resize(cur.len(), 0);
            let rects = self.encode_runs(&cur, (0..h).step_by(TILE).map(|y| (y, 0, w)).collect());
            self.scaled = std::mem::replace(&mut self.prev, cur);
            return rects;
        }

        let stride = w * 4;
        let mut runs = Vec::new();
        for ty in (0..h).step_by(TILE) {
            let th = TILE.min(h - ty);
            let cols = w.div_ceil(TILE);
            let mut start: Option<usize> = None;
            for tx in 0..=cols {
                let dirty = tx < cols && {
                    let x0 = tx * TILE * 4;
                    let x1 = ((tx + 1) * TILE).min(w) * 4;
                    (ty..ty + th).any(|y| cur[y * stride + x0..y * stride + x1] != self.prev[y * stride + x0..y * stride + x1])
                };
                match (dirty, start) {
                    (true, None) => start = Some(tx),
                    (false, Some(s)) => {
                        runs.push((ty, s * TILE, (tx * TILE).min(w)));
                        start = None;
                    }
                    _ => {}
                }
            }
        }
        let rects = self.encode_runs(&cur, runs);
        self.scaled = std::mem::replace(&mut self.prev, cur);
        rects
    }

    /// Next frame covers the whole picture.
    pub fn reset(&mut self) {
        self.full = true;
    }

    /// `(y, x0, x1)` runs, each `TILE` rows tall (less at the bottom edge).
    fn encode_runs(&self, cur: &[u8], runs: Vec<(usize, usize, usize)>) -> Vec<Rect> {
        let stride = self.width * 4;
        let mut buf = Vec::new();
        runs.into_iter()
            .filter_map(|(y, x0, x1)| {
                let rh = TILE.min(self.height - y);
                let rw = x1 - x0;
                buf.clear();
                for row in y..y + rh {
                    buf.extend_from_slice(&cur[row * stride + x0 * 4..row * stride + x1 * 4]);
                }
                let mut out = Vec::with_capacity(rw * rh / 4);
                let enc = jpeg_encoder::Encoder::new(&mut out, self.quality);
                enc.encode(&buf, rw as u16, rh as u16, jpeg_encoder::ColorType::Bgra).ok()?;
                Some(Rect { x: x0 as u16, y: y as u16, width: rw as u16, height: rh as u16, codec: Codec::Jpeg, data: out })
            })
            .collect()
    }
}

/// Box filter: each output pixel averages a `scale` x `scale` block.
fn downscale(img: &Image, scale: usize, out: &mut Vec<u8>) {
    let (w, h) = ((img.width / scale).max(1), (img.height / scale).max(1));
    out.clear();
    out.resize(w * h * 4, 0);
    let n = (scale * scale) as u32;
    for oy in 0..h {
        for ox in 0..w {
            let mut acc = [0u32; 4];
            for dy in 0..scale {
                let row = ((oy * scale + dy).min(img.height - 1)) * img.width * 4;
                for dx in 0..scale {
                    let p = row + (ox * scale + dx).min(img.width - 1) * 4;
                    for (a, v) in acc.iter_mut().zip(&img.data[p..p + 4]) {
                        *a += u32::from(*v);
                    }
                }
            }
            let o = (oy * w + ox) * 4;
            for (o, a) in out[o..o + 4].iter_mut().zip(acc) {
                *o = (a / n) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(w: usize, h: usize) -> Vec<u8> {
        (0..w * h * 4).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn first_frame_is_full_then_only_changes() {
        let (w, h) = (200, 130);
        let mut px = screen(w, h);
        let mut e = Encoder::new(60, 1);
        let rects = e.encode(&Image { data: &px, width: w, height: h });
        // One full-width rectangle per 64-row band.
        assert_eq!(rects.iter().map(|r| (r.y, r.width, r.height)).collect::<Vec<_>>(), [(0, 200, 64), (64, 200, 64), (128, 200, 2)]);
        assert!(rects.iter().all(|r| r.data.starts_with(&[0xff, 0xd8])));

        assert!(e.encode(&Image { data: &px, width: w, height: h }).is_empty(), "nothing changed");

        // Touch one pixel in tile (2, 1) and two adjacent tiles in band 0.
        px[(70 * w + 150) * 4] ^= 0xff;
        px[(3 * w + 10) * 4] ^= 0xff;
        px[(3 * w + 70) * 4] ^= 0xff;
        let rects = e.encode(&Image { data: &px, width: w, height: h });
        assert_eq!(rects.iter().map(|r| (r.x, r.y, r.width, r.height)).collect::<Vec<_>>(), [(0, 0, 128, 64), (128, 64, 64, 64)]);

        e.reset();
        assert_eq!(e.encode(&Image { data: &px, width: w, height: h }).len(), 3);
    }

    #[test]
    fn downscaled_output() {
        let (w, h) = (128, 64);
        let px = vec![200u8; w * h * 4];
        let mut e = Encoder::new(45, 2);
        assert_eq!(e.output_size(w, h), (64, 32));
        let rects = e.encode(&Image { data: &px, width: w, height: h });
        assert_eq!(rects.iter().map(|r| (r.width, r.height)).collect::<Vec<_>>(), [(64, 32)]);
    }
}
