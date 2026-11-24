//! Network discovery and SNMP monitoring, done by a designated agent per site.
//!
//! The server sends [`crate::ServerMsg::NetScan`] (find what is on the network) and
//! [`crate::ServerMsg::SnmpPoll`] (read some devices) and the agent answers with
//! [`crate::AgentMsg::NetScanResult`] and [`crate::AgentMsg::SnmpPollResult`] when it is
//! done. The agent keeps nothing: SNMP credentials arrive with each request and are never
//! written down.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Agents listing this in `Auth.capabilities` understand the messages in this module.
pub const CAPABILITY: &str = "network";

/// Agents listing this in `Auth.capabilities` send Wake-on-LAN packets
/// ([`crate::ServerMsg::WakeOnLan`]).
pub const WOL_CAPABILITY: &str = "wol";
/// The most machines one [`crate::ServerMsg::WakeOnLan`] wakes.
pub const MAX_WOL_TARGETS: usize = 512;

/// The most addresses one scan covers.
pub const MAX_SCAN_HOSTS: u32 = 4096;
/// The most devices in one poll request.
pub const MAX_POLL_TARGETS: usize = 64;
/// The most interfaces read from one device.
pub const MAX_INTERFACES: usize = 512;
/// What the agent answers for a device it didn't get to because it is still reading others.
pub const AGENT_BUSY: &str = "the agent is still reading other devices";
/// TCP ports a scan checks on live hosts: remote access, file sharing, web and printing.
pub const SCAN_PORTS: &[u16] = &[22, 23, 53, 80, 135, 139, 443, 445, 515, 631, 3389, 5900, 8080, 8443, 9100];

/// How to talk SNMP to a device. Protocol names are those of `rmm-snmp`: authentication
/// `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`; privacy `des`, `aes128`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "version", rename_all = "snake_case")]
pub enum SnmpCreds {
    V2c {
        community: String,
    },
    V3 {
        user: String,
        #[serde(default)]
        auth_proto: Option<String>,
        #[serde(default)]
        auth_secret: Option<String>,
        #[serde(default)]
        priv_proto: Option<String>,
        #[serde(default)]
        priv_secret: Option<String>,
        #[serde(default)]
        context: String,
    },
}

// Credentials never reach a log line.
impl fmt::Debug for SnmpCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpCreds::V2c { .. } => f.write_str("SnmpCreds::V2c(..)"),
            SnmpCreds::V3 { user, .. } => write!(f, "SnmpCreds::V3({user:?}, ..)"),
        }
    }
}

/// A set of credentials to try on every live host of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpProfile {
    pub id: Uuid,
    pub creds: SnmpCreds,
    #[serde(default = "default_port")]
    pub port: u16,
}

pub fn default_port() -> u16 {
    161
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSpec {
    /// CIDR blocks, IPv4. Empty: the subnets the agent's own interfaces are on (each at most
    /// a /22 around the agent's address).
    #[serde(default)]
    pub subnets: Vec<String>,
    /// Never scan more addresses than this ([`MAX_SCAN_HOSTS`] at most).
    pub max_hosts: u32,
    /// Credentials tried on each live host, in order, until one answers.
    #[serde(default)]
    pub profiles: Vec<SnmpProfile>,
    /// Look up names: reverse DNS and mDNS.
    #[serde(default = "yes")]
    pub names: bool,
}

fn yes() -> bool {
    true
}

/// What a device said about itself over SNMP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysInfo {
    #[serde(default)]
    pub descr: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub object_id: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub contact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpIdent {
    /// The profile that worked.
    pub profile_id: Uuid,
    pub sys: SysInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub ip: String,
    /// `aa:bb:cc:dd:ee:ff`, when the agent could see it (hosts on its own subnets).
    #[serde(default)]
    pub mac: Option<String>,
    /// Reverse DNS.
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub mdns_name: Option<String>,
    /// How the host was found: `arp`, `icmp`, `tcp`, `snmp`.
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub open_ports: Vec<u16>,
    #[serde(default)]
    pub snmp: Option<SnmpIdent>,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollTarget {
    pub device_id: Uuid,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub creds: SnmpCreds,
    /// Read Printer-MIB supplies too.
    #[serde(default)]
    pub supplies: bool,
}

/// An IF-MIB interface, as read. Counters are the 64-bit ones where the device has them
/// (`hc`), the 32-bit ones otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    #[serde(default)]
    pub descr: String,
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub if_type: i32,
    #[serde(default)]
    pub speed_bps: u64,
    /// ifAdminStatus: 1 up, 2 down, 3 testing.
    pub admin_status: i32,
    /// ifOperStatus: 1 up, 2 down, 3 testing, 4 unknown, 5 dormant, 6 notPresent, 7 lowerLayerDown.
    pub oper_status: i32,
    pub in_octets: u64,
    pub out_octets: u64,
    #[serde(default)]
    pub in_errors: u64,
    #[serde(default)]
    pub out_errors: u64,
    #[serde(default)]
    pub in_discards: u64,
    #[serde(default)]
    pub out_discards: u64,
    pub hc: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Storage {
    pub descr: String,
    /// `ram` or `disk`.
    pub kind: String,
    pub total: u64,
    pub used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Supply {
    pub index: u32,
    pub description: String,
    /// prtMarkerSuppliesClass: 3 consumed (toner, ink), 4 filled (waste).
    pub class: i32,
    /// prtMarkerSuppliesType: 3 toner, 4 wasteToner, 5 ink, 9 opc, 12 fuser...
    pub kind: i32,
    /// Percent full (or, for waste, how full the container is as the device reports it); `None`
    /// when the device doesn't know (`-2`) or only says some is left (`-3`).
    pub percent: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PollResult {
    pub device_id: Uuid,
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    /// How long the first request took.
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub sys: Option<SysInfo>,
    #[serde(default)]
    pub uptime_secs: Option<u64>,
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub cpu_percent: Option<f32>,
    #[serde(default)]
    pub mem_total: Option<u64>,
    #[serde(default)]
    pub mem_used: Option<u64>,
    #[serde(default)]
    pub storage: Vec<Storage>,
    #[serde(default)]
    pub supplies: Vec<Supply>,
}

impl Default for Interface {
    fn default() -> Self {
        Interface {
            index: 0,
            name: String::new(),
            descr: String::new(),
            alias: String::new(),
            if_type: 0,
            speed_bps: 0,
            admin_status: 1,
            oper_status: 1,
            in_octets: 0,
            out_octets: 0,
            in_errors: 0,
            out_errors: 0,
            in_discards: 0,
            out_discards: 0,
            hc: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Wake-on-LAN
// ---------------------------------------------------------------------------

/// A machine to wake: its MAC address (`aa:bb:cc:dd:ee:ff`) and the IPv4 addresses it last
/// had (`10.0.0.5/24`, as in [`crate::NetInterface::addrs`]), so the sender can pick the
/// interface on the same subnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WolTarget {
    pub mac: String,
    #[serde(default)]
    pub last_ip: Vec<String>,
}
