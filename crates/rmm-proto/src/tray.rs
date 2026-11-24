//! The end-user tray app (docs/design/tray.md).
//!
//! The server sends [`Config`] ([`crate::ServerMsg::TrayConfig`]) after connecting and whenever
//! the device's `tray` policy or its client's branding changes; the agent keeps it on disk so
//! the contact card works offline. A help request from the person at the machine goes up as
//! [`crate::AgentMsg::HelpRequest`], then its screenshot (if any) in
//! [`crate::AgentMsg::HelpAttachment`] pieces, and is answered with
//! [`crate::ServerMsg::HelpRequestResult`]. Only agents listing [`CAPABILITY`] get these.

use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "tray";

/// Longest subject, in characters.
pub const MAX_SUBJECT: usize = 300;
/// Longest description, in characters.
pub const MAX_BODY: usize = 5_000;
/// Largest screenshot, in bytes.
pub const MAX_SCREENSHOT: usize = 5 * 1024 * 1024;
/// Screenshot bytes per [`crate::AgentMsg::HelpAttachment`].
pub const CHUNK: usize = 256 * 1024;
/// At most this many links on the menu.
pub const MAX_LINKS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Config {
    /// Off: the tray shows nothing but the contact card is still cached.
    pub enabled: bool,
    /// The branded product name, or the built-in one.
    pub product_name: String,
    /// The branding icon (a square PNG), when one is set.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    pub icon_png: Vec<u8>,
    /// Shown only when the policy's `contact_card` is on; otherwise all empty.
    #[serde(default)]
    pub contact: Contact,
    #[serde(default)]
    pub links: Vec<Link>,
    /// The "Request help" entry.
    pub request_help: bool,
    /// Whether "attach a screenshot" starts ticked.
    pub screenshot_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Contact {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub hours: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub label: String,
    pub url: String,
}

/// What the agent knows about the machine when the request is made. The server adds what it
/// has itself (open alerts, the last inventory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Context {
    #[serde(default)]
    pub uptime_secs: u64,
    /// The machine's own addresses.
    #[serde(default)]
    pub ips: Vec<String>,
    /// The request waited this long on the machine (the server was unreachable).
    #[serde(default)]
    pub queued_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_old_peers() {
        let c = Config {
            enabled: true,
            product_name: "Acme".into(),
            icon_png: vec![1, 2, 3],
            contact: Contact { name: "Acme IT".into(), phone: "555".into(), ..Default::default() },
            links: vec![Link { label: "Status".into(), url: "https://status.example".into() }],
            request_help: true,
            screenshot_default: false,
        };
        let back: Config = crate::decode(&crate::encode(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        // A server that sends no icon, contact or links.
        #[derive(Serialize)]
        struct Old {
            enabled: bool,
            product_name: String,
            request_help: bool,
            screenshot_default: bool,
        }
        let old = Old { enabled: false, product_name: "RMM".into(), request_help: false, screenshot_default: true };
        let back: Config = crate::decode(&crate::encode(&old).unwrap()).unwrap();
        assert!(back.icon_png.is_empty() && back.links.is_empty() && back.contact == Contact::default());
    }
}
