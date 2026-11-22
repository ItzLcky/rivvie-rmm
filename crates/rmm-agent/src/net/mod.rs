//! Network discovery and SNMP polling for the site's designated agent (see
//! [`rmm_proto::net`]). Nothing here is remembered: the server asks, the agent does it and
//! answers.

mod addr;
mod arp;
mod dns;
mod icmp;
pub mod poll;
mod scan;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rmm_proto::AgentMsg;
use rmm_proto::net::{MAX_POLL_TARGETS, PollTarget, ScanSpec};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

/// One scan at a time: a second request while one runs is answered at once with an error.
static SCANNING: AtomicBool = AtomicBool::new(false);
/// One poll at a time too; the server doesn't send the next before the last is answered, and
/// a device read slowly must not pile up.
static POLLING: AtomicBool = AtomicBool::new(false);

struct Busy(&'static AtomicBool);

impl Busy {
    fn take(flag: &'static AtomicBool) -> Option<Busy> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).ok().map(|_| Busy(flag))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub async fn scan(scan_id: Uuid, spec: ScanSpec, tx: mpsc::Sender<AgentMsg>) {
    let Some(_busy) = Busy::take(&SCANNING) else {
        let msg = AgentMsg::NetScanResult {
            scan_id,
            subnets: vec![],
            scanned: 0,
            hosts: vec![],
            error: Some("this agent is already running a scan".into()),
            duration_ms: 0,
        };
        let _ = tx.send(msg).await;
        return;
    };
    let started = Instant::now();
    info!(%scan_id, subnets = ?spec.subnets, "network scan started");
    let out = scan::run(&spec, false).await;
    info!(%scan_id, scanned = out.scanned, found = out.hosts.len(), "network scan finished");
    let _ = tx
        .send(AgentMsg::NetScanResult {
            scan_id,
            subnets: out.subnets,
            scanned: out.scanned,
            hosts: out.hosts,
            error: out.error,
            duration_ms: started.elapsed().as_millis() as u64,
        })
        .await;
}

pub async fn snmp_poll(poll_id: Uuid, mut targets: Vec<PollTarget>, tx: mpsc::Sender<AgentMsg>) {
    targets.truncate(MAX_POLL_TARGETS);
    let Some(_busy) = Busy::take(&POLLING) else {
        warn!(%poll_id, "an SNMP poll is still running; refusing another");
        let results = targets
            .iter()
            .map(|t| rmm_proto::net::PollResult { device_id: t.device_id, error: Some(rmm_proto::net::AGENT_BUSY.into()), ..Default::default() })
            .collect();
        let _ = tx.send(AgentMsg::SnmpPollResult { poll_id, results }).await;
        return;
    };
    let results = poll::poll(targets).await;
    let _ = tx.send(AgentMsg::SnmpPollResult { poll_id, results }).await;
}

#[cfg(test)]
mod tests {
    use rmm_proto::net::{SnmpCreds, SnmpProfile};
    use rmm_snmp::sim::{self, Sim};

    use super::*;

    /// A scan of the loopback address finds the simulated device, its SNMP identity and its open port.
    #[tokio::test]
    async fn a_scan_finds_a_host_and_identifies_it() {
        let s = Sim::start("public", sim::system("Acme firewall", "1.3.6.1.4.1.12356.101.1.1", "fw1", 1)).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _ = listener.local_addr().unwrap();
        let profile_id = Uuid::new_v4();
        let spec = ScanSpec {
            subnets: vec!["127.0.0.1/32".into()],
            max_hosts: 16,
            profiles: vec![
                SnmpProfile { id: Uuid::new_v4(), creds: SnmpCreds::V2c { community: "wrong".into() }, port: s.addr.port() },
                SnmpProfile { id: profile_id, creds: SnmpCreds::V2c { community: "public".into() }, port: s.addr.port() },
            ],
            names: false,
        };
        let out = scan::run(&spec, true).await;
        assert_eq!((out.scanned, out.error), (1, None));
        assert_eq!(out.hosts.len(), 1, "{:?}", out.hosts);
        let h = &out.hosts[0];
        assert_eq!(h.ip, "127.0.0.1");
        let ident = h.snmp.as_ref().expect("the second profile answers");
        assert_eq!((ident.profile_id, ident.sys.name.as_str()), (profile_id, "fw1"));
        assert!(h.methods.contains(&"snmp".to_string()) && h.methods.contains(&"tcp".to_string()), "{:?}", h.methods);
    }

    #[tokio::test]
    async fn a_scan_stays_in_private_space_and_within_its_limit() {
        // A public block: nothing is probed.
        let spec = ScanSpec { subnets: vec!["8.8.8.0/30".into()], max_hosts: 16, profiles: vec![], names: false };
        let out = scan::run(&spec, false).await;
        assert_eq!((out.scanned, out.hosts.len()), (0, 0));
        // Over the limit: stops at it and says so.
        let spec = ScanSpec { subnets: vec!["10.254.0.0/24".into()], max_hosts: 4, profiles: vec![], names: false };
        let out = tokio::time::timeout(std::time::Duration::from_secs(30), scan::run(&spec, false)).await.unwrap();
        assert_eq!(out.scanned, 4);
        assert!(out.error.unwrap().contains("more than 4"));
        let bad = scan::run(&ScanSpec { subnets: vec!["not a block".into()], max_hosts: 4, profiles: vec![], names: false }, false).await;
        assert!(bad.error.is_some() && bad.hosts.is_empty());
    }

    #[tokio::test]
    async fn only_one_scan_at_a_time() {
        let _held = Busy::take(&SCANNING).expect("free at first");
        let (tx, mut rx) = mpsc::channel(4);
        scan(Uuid::new_v4(), ScanSpec { subnets: vec![], max_hosts: 4, profiles: vec![], names: false }, tx).await;
        match rx.recv().await.unwrap() {
            AgentMsg::NetScanResult { error, hosts, .. } => assert!(error.unwrap().contains("already") && hosts.is_empty()),
            other => panic!("{other:?}"),
        }
    }
}
