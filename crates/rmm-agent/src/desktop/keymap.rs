//! Physical keys: W3C `KeyboardEvent.code` to Linux evdev codes and PC scan codes.
//!
//! Keys are sent by position, so the remote machine's own layout decides the character,
//! as with a keyboard plugged into it. X servers using evdev/libinput number keys as
//! evdev + 8.

// Only the X11 and Windows backends inject keys.
#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]

/// How Windows `SendInput` should press a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinKey {
    /// Set-1 scan code; `true` for the E0-prefixed (extended) keys.
    Scan(u16, bool),
    /// Keys without a usable scan code for `SendInput` (Pause, NumLock, F13+).
    Vk(u16),
}

pub struct Key {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub evdev: u16,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub win: WinKey,
}

/// Scan code equals the evdev code for the whole classic PC/AT block.
const fn at(evdev: u16) -> Key {
    Key { evdev, win: WinKey::Scan(evdev, false) }
}

const fn ext(evdev: u16, scan: u16) -> Key {
    Key { evdev, win: WinKey::Scan(scan, true) }
}

const fn vk(evdev: u16, vk: u16) -> Key {
    Key { evdev, win: WinKey::Vk(vk) }
}

pub fn lookup(code: &str) -> Option<Key> {
    let letters = "QWERTYUIOP";
    let home = "ASDFGHJKL";
    let bottom = "ZXCVBNM";
    if let Some(l) = code.strip_prefix("Key").filter(|l| l.len() == 1) {
        let c = l.chars().next()?;
        let row = |s: &str, base: u16| s.find(c).map(|i| at(base + i as u16));
        return row(letters, 16).or_else(|| row(home, 30)).or_else(|| row(bottom, 44));
    }
    if let Some(d) = code.strip_prefix("Digit").and_then(|d| d.parse::<u16>().ok()).filter(|d| *d <= 9) {
        return Some(at(if d == 0 { 11 } else { d + 1 }));
    }
    if let Some(n) = code.strip_prefix('F').and_then(|n| n.parse::<u16>().ok()) {
        return match n {
            1..=10 => Some(at(58 + n)),
            11 | 12 => Some(at(76 + n)),
            // VK_F13 = 0x7C.
            13..=24 => Some(vk(170 + n, 0x7c + n - 13)),
            _ => None,
        };
    }
    Some(match code {
        "Escape" => at(1),
        "Minus" => at(12),
        "Equal" => at(13),
        "Backspace" => at(14),
        "Tab" => at(15),
        "BracketLeft" => at(26),
        "BracketRight" => at(27),
        "Enter" => at(28),
        "ControlLeft" => at(29),
        "Semicolon" => at(39),
        "Quote" => at(40),
        "Backquote" => at(41),
        "ShiftLeft" => at(42),
        "Backslash" => at(43),
        "Comma" => at(51),
        "Period" => at(52),
        "Slash" => at(53),
        "ShiftRight" => at(54),
        "NumpadMultiply" => at(55),
        "AltLeft" => at(56),
        "Space" => at(57),
        "CapsLock" => at(58),
        "NumLock" => vk(69, 0x90),
        "ScrollLock" => at(70),
        "Numpad7" => at(71),
        "Numpad8" => at(72),
        "Numpad9" => at(73),
        "NumpadSubtract" => at(74),
        "Numpad4" => at(75),
        "Numpad5" => at(76),
        "Numpad6" => at(77),
        "NumpadAdd" => at(78),
        "Numpad1" => at(79),
        "Numpad2" => at(80),
        "Numpad3" => at(81),
        "Numpad0" => at(82),
        "NumpadDecimal" => at(83),
        "IntlBackslash" => at(86),
        "IntlRo" => Key { evdev: 89, win: WinKey::Scan(0x73, false) },
        "IntlYen" => Key { evdev: 124, win: WinKey::Scan(0x7d, false) },
        "NumpadEqual" => Key { evdev: 117, win: WinKey::Scan(0x59, false) },
        "NumpadEnter" => ext(96, 0x1c),
        "ControlRight" => ext(97, 0x1d),
        "NumpadDivide" => ext(98, 0x35),
        "PrintScreen" => ext(99, 0x37),
        "AltRight" => ext(100, 0x38),
        "Home" => ext(102, 0x47),
        "ArrowUp" => ext(103, 0x48),
        "PageUp" => ext(104, 0x49),
        "ArrowLeft" => ext(105, 0x4b),
        "ArrowRight" => ext(106, 0x4d),
        "End" => ext(107, 0x4f),
        "ArrowDown" => ext(108, 0x50),
        "PageDown" => ext(109, 0x51),
        "Insert" => ext(110, 0x52),
        "Delete" => ext(111, 0x53),
        "AudioVolumeMute" => ext(113, 0x20),
        "AudioVolumeDown" => ext(114, 0x2e),
        "AudioVolumeUp" => ext(115, 0x30),
        "Pause" => vk(119, 0x13),
        "MetaLeft" => ext(125, 0x5b),
        "MetaRight" => ext(126, 0x5c),
        "ContextMenu" => ext(127, 0x5d),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes() {
        let e = |c| lookup(c).map(|k| k.evdev);
        assert_eq!((e("KeyQ"), e("KeyA"), e("KeyM"), e("KeyL")), (Some(16), Some(30), Some(50), Some(38)));
        assert_eq!((e("Digit1"), e("Digit0"), e("F1"), e("F10"), e("F11"), e("F12"), e("F13")), (Some(2), Some(11), Some(59), Some(68), Some(87), Some(88), Some(183)));
        assert_eq!(lookup("ArrowLeft").unwrap().win, WinKey::Scan(0x4b, true));
        assert_eq!(lookup("F13").unwrap().win, WinKey::Vk(0x7c));
        assert!(lookup("KeyÄ").is_none() && lookup("Unidentified").is_none() && lookup("F25").is_none());
    }
}
