//! Remote desktop payloads.
//!
//! The server opens a session with [`crate::ServerMsg::DesktopOpen`]. The agent answers
//! with [`crate::AgentMsg::DesktopInfo`] (the monitors, sent again whenever they or the
//! selection change) and then a stream of [`crate::AgentMsg::DesktopFrame`]s, until either
//! side closes it ([`crate::ServerMsg::DesktopClose`] / [`crate::AgentMsg::DesktopClosed`]).
//!
//! Frames are paced by acknowledgements: the agent keeps at most [`FRAME_WINDOW`] frames
//! unacknowledged ([`crate::ServerMsg::DesktopAck`], sent once the browser has drawn a
//! frame). A slow link therefore gets fewer, fresher frames instead of a growing backlog,
//! and the agent socket stays free for heartbeats and jobs.
//!
//! The first frame after opening, and after any settings change, covers the whole screen.
//! Later frames only carry the rectangles that changed.

use serde::{Deserialize, Serialize};

/// Capability an agent lists in `Auth` when it can serve remote desktop sessions.
pub const CAPABILITY: &str = "desktop";

/// Frames the agent may have in flight before it waits for an acknowledgement.
pub const FRAME_WINDOW: u32 = 2;

/// Longest [`InputEvent::Text`] the agent types, in characters.
pub const TEXT_MAX: usize = 4096;

/// Picture quality. Lower settings trade sharpness for bandwidth.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    /// Half resolution, heavier compression: for slow links.
    Low,
    #[default]
    Balanced,
    /// Full resolution, light compression.
    High,
}

impl Quality {
    /// JPEG quality (1-100) and the downscale divisor.
    pub fn params(self) -> (u8, u32) {
        match self {
            Quality::Low => (45, 2),
            Quality::Balanced => (65, 1),
            Quality::High => (85, 1),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Settings {
    /// Index into [`Monitor`]s; out of range falls back to the primary.
    #[serde(default)]
    pub monitor: u32,
    #[serde(default)]
    pub quality: Quality,
}

/// Ask the person at the machine before the session starts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Consent {
    /// Shown in the prompt: who wants to connect.
    pub requester: String,
    /// Shown in the prompt: the MSP's name (Company settings).
    pub company: String,
    /// Deny when nobody answers within this many seconds.
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Monitor {
    pub name: String,
    /// Position on the virtual desktop and size, in physical pixels.
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Codec {
    /// Baseline JPEG, 4:2:0.
    Jpeg,
}

impl Codec {
    pub fn id(self) -> u8 {
        match self {
            Codec::Jpeg => 1,
        }
    }
}

/// One changed area of the picture, in frame pixels (after downscaling).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub codec: Codec,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Frame {
    /// Increases by one per frame within a session; what [`crate::ServerMsg::DesktopAck`] names.
    pub seq: u32,
    /// The captured monitor's size in physical pixels: what input coordinates refer to.
    pub screen_width: u32,
    pub screen_height: u32,
    /// The picture's size (smaller than the screen at [`Quality::Low`]).
    pub width: u32,
    pub height: u32,
    /// Changed areas. Empty when only the cursor moved or nothing changed.
    pub rects: Vec<Rect>,
    /// Pointer position in screen pixels, when the platform reports it.
    #[serde(default)]
    pub cursor: Option<(i32, i32)>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Button {
    Left,
    Middle,
    Right,
    Back,
    Forward,
}

/// Keyboard and pointer input. Coordinates are screen pixels of the captured monitor
/// (see [`Frame::screen_width`]); the agent clamps them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum InputEvent {
    Move { x: i32, y: i32 },
    Button { button: Button, down: bool, x: i32, y: i32 },
    /// Wheel notches; positive `dy` scrolls down, positive `dx` right.
    Wheel { dx: i32, dy: i32 },
    /// A physical key by its W3C `KeyboardEvent.code` (`KeyA`, `ShiftLeft`, `F5`...). The
    /// machine's own keyboard layout decides which character it produces.
    Key { code: String, down: bool },
    /// Types this text as if from a keyboard, independent of the layout.
    Text { text: String },
    /// The secure attention sequence. Windows needs `SendSAS` for it; elsewhere the agent
    /// presses the three keys.
    CtrlAltDel,
}

impl InputEvent {
    /// Server-side sanity check on browser input.
    pub fn valid(&self) -> bool {
        match self {
            InputEvent::Key { code, .. } => !code.is_empty() && code.len() <= 32 && code.bytes().all(|b| b.is_ascii_alphanumeric()),
            InputEvent::Text { text } => text.chars().count() <= TEXT_MAX,
            InputEvent::Wheel { dx, dy } => dx.abs() <= 100 && dy.abs() <= 100,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_json_input_parses() {
        let ev: Vec<InputEvent> = serde_json::from_str(
            r#"[{"t":"move","x":10,"y":20},{"t":"button","button":"left","down":true,"x":1,"y":2},
                {"t":"key","code":"KeyA","down":false},{"t":"wheel","dx":0,"dy":-3},{"t":"ctrl_alt_del"}]"#,
        )
        .unwrap();
        assert_eq!(ev.len(), 5);
        assert!(ev.iter().all(InputEvent::valid));
        assert!(!InputEvent::Key { code: "Key A".into(), down: true }.valid());
        assert!(!InputEvent::Text { text: "x".repeat(TEXT_MAX + 1) }.valid());
    }

    #[test]
    fn frame_roundtrips() {
        let f = Frame {
            seq: 7,
            screen_width: 1920,
            screen_height: 1080,
            width: 960,
            height: 540,
            rects: vec![Rect { x: 0, y: 64, width: 960, height: 64, codec: Codec::Jpeg, data: vec![0xff, 0xd8] }],
            cursor: Some((5, 6)),
        };
        assert_eq!(crate::decode::<Frame>(&crate::encode(&f).unwrap()).unwrap(), f);
    }
}
