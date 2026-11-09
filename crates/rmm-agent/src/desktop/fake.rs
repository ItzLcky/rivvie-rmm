//! A synthetic screen for tests (`RMM_DESKTOP_FAKE=<file>`): two monitors with a moving
//! block, and every input event appended to `<file>` as a JSON line.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use rmm_proto::desktop::{InputEvent, Monitor};

pub struct FakeScreen {
    log: PathBuf,
    tick: usize,
    cursor: (i32, i32),
}

impl FakeScreen {
    pub fn new(log: PathBuf) -> Self {
        FakeScreen { log, tick: 0, cursor: (0, 0) }
    }
}

impl super::Screen for FakeScreen {
    fn monitors(&mut self) -> Result<Vec<Monitor>> {
        Ok(vec![
            Monitor { name: "FAKE-1".into(), x: 0, y: 0, width: 640, height: 360, primary: true },
            Monitor { name: "FAKE-2".into(), x: 640, y: 0, width: 320, height: 240, primary: false },
        ])
    }

    fn capture(&mut self, m: &Monitor, buf: &mut Vec<u8>) -> Result<()> {
        let (w, h) = (m.width as usize, m.height as usize);
        buf.clear();
        buf.resize(w * h * 4, 0);
        for y in 0..h {
            for x in 0..w {
                let p = (y * w + x) * 4;
                buf[p] = (x * 255 / w) as u8;
                buf[p + 1] = (y * 255 / h) as u8;
                buf[p + 2] = 96;
            }
        }
        // A 32x32 white block that moves 8 px per capture.
        let bx = (self.tick * 8) % (w - 32);
        self.tick += 1;
        for y in 0..32.min(h) {
            for x in bx..bx + 32 {
                let p = (y * w + x) * 4;
                buf[p..p + 3].copy_from_slice(&[255, 255, 255]);
            }
        }
        Ok(())
    }

    fn cursor(&mut self) -> Option<(i32, i32)> {
        Some(self.cursor)
    }

    fn input(&mut self, m: &Monitor, ev: &InputEvent) -> Result<()> {
        if let InputEvent::Move { x, y } | InputEvent::Button { x, y, .. } = ev {
            self.cursor = super::absolute(m, *x, *y);
        }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.log)?;
        writeln!(f, "{}", serde_json::to_string(ev)?)?;
        Ok(())
    }
}
