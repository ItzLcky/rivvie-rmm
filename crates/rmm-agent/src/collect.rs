//! Metrics and inventory collection. Kept in one long-lived struct so sysinfo
//! can reuse allocations and compute CPU usage deltas between samples.

use chrono::Utc;
use rmm_proto::{DiskInfo, DiskUsage, Inventory, Metrics, NetInterface, OsFamily, Platform, SystemInfo};
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, Users};

use crate::software;

/// `RMM_AGENT_VERSION` at build time overrides the crate version (release builds, tests).
/// (Empty counts as unset: Docker build args are always defined.)
pub const AGENT_VERSION: &str = match option_env!("RMM_AGENT_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

pub struct Collector {
    sys: System,
    disks: Disks,
    networks: Networks,
}

impl Collector {
    pub fn new() -> anyhow::Result<Self> {
        let sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_usage())
                .with_memory(MemoryRefreshKind::everything()),
        )?;
        Ok(Self {
            sys,
            disks: Disks::new_with_refreshed_list()?,
            networks: Networks::new_with_refreshed_list()?,
        })
    }

    pub fn metrics(&mut self) -> Metrics {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
        self.disks.refresh(true);
        self.networks.refresh(true);

        let load = System::load_average().ok();
        let (rx, tx) = self
            .networks
            .iter()
            .filter(|(name, _)| !is_loopback(&name.to_string_lossy()))
            .fold((0, 0), |(rx, tx), (_, n)| (rx + n.total_received(), tx + n.total_transmitted()));

        Metrics {
            ts: Utc::now(),
            uptime_secs: System::uptime().unwrap_or(0),
            cpu_percent: self.sys.global_cpu_usage(),
            load_avg: load.filter(|_| !cfg!(windows)).map(|l| [l.one, l.five, l.fifteen]),
            mem_total: self.sys.total_memory(),
            mem_used: self.sys.used_memory(),
            swap_total: self.sys.total_swap(),
            swap_used: self.sys.used_swap(),
            disks: local_disks(&self.disks)
                .map(|d| DiskUsage {
                    mount: d.mount_point().to_string_lossy().into_owned(),
                    total: d.total_space(),
                    available: d.available_space(),
                })
                .collect(),
            net_rx_bytes: rx,
            net_tx_bytes: tx,
            process_count: self.sys.processes().len() as u32,
        }
    }

    pub fn inventory(&mut self) -> Inventory {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.disks.refresh(true);
        self.networks.refresh(true);

        let cpu_brand = self.sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default();
        let users = Users::new_with_refreshed_list().map(Vec::from).unwrap_or_default();

        Inventory {
            collected_at: Utc::now(),
            system: system_info(),
            cpu_brand,
            cpu_cores_physical: System::physical_core_count().ok().map(|n| n as u32),
            cpu_cores_logical: self.sys.cpus().len() as u32,
            mem_total: self.sys.total_memory(),
            disks: local_disks(&self.disks)
                .map(|d| DiskInfo {
                    name: d.name().to_string_lossy().into_owned(),
                    mount: d.mount_point().to_string_lossy().into_owned(),
                    fs: d.file_system().to_string_lossy().into_owned(),
                    kind: format!("{:?}", d.kind()),
                    removable: d.is_removable(),
                    total: d.total_space(),
                })
                .collect(),
            network: self
                .networks
                .iter()
                .filter(|(name, _)| !is_loopback(&name.to_string_lossy()))
                .map(|(name, n)| NetInterface {
                    name: name.to_string_lossy().into_owned(),
                    mac: n.mac_address().to_string(),
                    addrs: n.ip_networks().iter().map(|ip| format!("{}/{}", ip.addr, ip.prefix)).collect(),
                })
                .collect(),
            software: software::installed(),
            // sysinfo lists accounts, not sessions; good enough until we add utmp/WTS session enumeration.
            logged_in_users: users.iter().filter(|u| is_human_user(u)).map(|u| u.name().to_string()).collect(),
        }
    }
}

pub fn system_info() -> SystemInfo {
    SystemInfo {
        hostname: System::host_name().unwrap_or_else(|_| "unknown".into()),
        os_family: OsFamily::current(),
        os_name: System::name().unwrap_or_default(),
        os_version: System::long_os_version().or_else(|_| System::os_version()).unwrap_or_default(),
        kernel_version: System::kernel_version().unwrap_or_default(),
        arch: System::cpu_arch(),
        agent_version: AGENT_VERSION.to_string(),
        machine_id: machine_id(),
        platform: platform(),
    }
}

fn is_loopback(name: &str) -> bool {
    name == "lo" || name.starts_with("Loopback")
}

/// Physical, local volumes only: skips pseudo and network filesystems, and
/// collapses btrfs/zfs subvolumes (same device, many mounts) to the shortest mount.
fn local_disks(disks: &Disks) -> impl Iterator<Item = &sysinfo::Disk> {
    let mut best: Vec<&sysinfo::Disk> = Vec::new();
    for d in disks.iter() {
        let fs = d.file_system().to_string_lossy();
        if matches!(
            fs.as_ref(),
            "tmpfs" | "devtmpfs" | "overlay" | "squashfs" | "efivarfs" | "proc" | "sysfs" | "ramfs"
                | "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "9p" | "virtiofs"
        ) || fs.starts_with("fuse")
        {
            continue;
        }
        match best.iter_mut().find(|b| b.name() == d.name()) {
            Some(b) if d.mount_point().as_os_str().len() < b.mount_point().as_os_str().len() => *b = d,
            Some(_) => {}
            None => best.push(d),
        }
    }
    best.into_iter()
}

#[cfg(unix)]
fn is_human_user(u: &sysinfo::User) -> bool {
    // Regular accounts on Linux start at uid 1000, on macOS at 501.
    let uid: u32 = **u.id();
    let min = if cfg!(target_os = "macos") { 501 } else { 1000 };
    uid >= min && uid < 60000
}

#[cfg(not(unix))]
fn is_human_user(_u: &sysinfo::User) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(windows)]
fn machine_id() -> Option<String> {
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .and_then(|k| k.get_value::<String, _>("MachineGuid"))
        .ok()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn machine_id() -> Option<String> {
    None
}

/// DMI chassis types of portable machines: portable, laptop, notebook, hand held, sub notebook,
/// tablet, convertible, detachable.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PORTABLE_CHASSIS: [u32; 8] = [8, 9, 10, 11, 14, 30, 31, 32];

/// Linux: a workstation when the chassis is portable or the machine boots to a desktop
/// (`graphical.target`), otherwise a server.
#[cfg(target_os = "linux")]
fn platform() -> Option<Platform> {
    let chassis = std::fs::read_to_string("/sys/class/dmi/id/chassis_type").ok().and_then(|s| s.trim().parse::<u32>().ok());
    // `systemctl get-default` without running it: the default.target link, admin's first.
    let target = ["/etc/systemd/system/default.target", "/usr/lib/systemd/system/default.target", "/lib/systemd/system/default.target"]
        .iter()
        .find_map(|p| std::fs::read_link(p).ok())
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
    Some(linux_platform(chassis, target.as_deref()))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_platform(chassis: Option<u32>, default_target: Option<&str>) -> Platform {
    if chassis.is_some_and(|c| PORTABLE_CHASSIS.contains(&c)) || default_target == Some("graphical.target") {
        Platform::Workstation
    } else {
        Platform::Server
    }
}

/// Windows: `ProductType` is `WinNT` on client editions, `ServerNT` or `LanmanNT` (a domain
/// controller) on servers.
#[cfg(windows)]
fn platform() -> Option<Platform> {
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
    let product: String = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SYSTEM\\CurrentControlSet\\Control\\ProductOptions")
        .and_then(|k| k.get_value("ProductType"))
        .ok()?;
    Some(if product.eq_ignore_ascii_case("WinNT") { Platform::Workstation } else { Platform::Server })
}

#[cfg(target_os = "macos")]
fn platform() -> Option<Platform> {
    Some(Platform::Workstation)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform() -> Option<Platform> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_platform_from_chassis_and_target() {
        assert_eq!(linux_platform(Some(10), Some("multi-user.target")), Platform::Workstation, "a notebook");
        assert_eq!(linux_platform(Some(3), Some("graphical.target")), Platform::Workstation, "a desktop");
        assert_eq!(linux_platform(Some(17), Some("multi-user.target")), Platform::Server, "a rack server");
        assert_eq!(linux_platform(None, None), Platform::Server, "a VM or container");
    }
}
