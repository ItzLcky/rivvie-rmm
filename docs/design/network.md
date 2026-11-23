# Network discovery and SNMP monitoring

A site's **designated agent** looks at the network it sits on: it finds what is there (discovery) and reads switches, firewalls, printers and similar devices over SNMP (monitoring). Nothing is installed on those devices, and nothing new listens on the agent.

## Who does what

Each site chooses one agent (Network → Settings). The server asks it; the agent answers and forgets. It keeps no state: SNMP credentials arrive in each request, over the agent's TLS socket, and are never written down on the machine. Agents list the `network` capability when they connect; the server only designates and only sends to ones that do.

| Message | Direction | What |
|---|---|---|
| `NetScan { scan_id, spec }` | server → agent | Scan these blocks (or the agent's own subnets), try these SNMP credentials on live hosts. |
| `NetScanResult { scan_id, subnets, scanned, hosts, error }` | agent → server | The hosts found, once the scan is over. |
| `SnmpPoll { poll_id, targets }` | server → agent | Read up to 64 devices. |
| `SnmpPollResult { poll_id, results }` | agent → server | One result per device, unreachable ones included. |

The server accepts a result only from the agent that was asked, and for devices that were in the request, so an agent can't write another site's data.

## Discovery

A scan is bounded: at most 4096 addresses, 128 probes in flight, a connection started every millisecond at most, ten minutes in all. It never leaves private address space (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16): the server refuses other blocks when they're configured, and the agent refuses them again. An agent is not a way to scan the internet. With no blocks configured it scans the subnets its own interfaces are on, narrowed to at most a /22 around its address.

Liveness needs no extra privileges:

1. **ICMP echo** over an unprivileged datagram socket where Linux allows it (root, or a group in `net.ipv4.ping_group_range`). Elsewhere this step is skipped.
2. **TCP connect** to a handful of common ports. An open port or a refusal both mean a host is there.
3. **The neighbour table** (`/proc/net/arp`, `arp -a`), read after the probes have made the kernel ask for each host's MAC address. A host that drops pings and refuses nothing still shows up here if it's on the agent's subnet; hosts on other subnets are found by 1 and 2, without a MAC.

Then, for each live host: the open ports among 15 common ones, reverse DNS (a PTR query to the system's resolvers), mDNS (a multicast browse of common service types, and a unicast reverse query to the host itself), and SNMP `sysDescr`, `sysObjectID`, `sysName`, `sysLocation` with each credential set of the site in turn until one answers. The **vendor** is looked up on the server from the MAC (`oui.txt.gz`, the IEEE's 24-bit registry, shortened; random locally-administered addresses have none). The **kind** (switch, router, firewall, printer, ap, ups, nas, windows, linux, other) is guessed from SNMP identity, vendor and ports, and can be corrected.

### Matching and the unmanaged list

A host is the same host across scans by MAC address (so a DHCP change of IP keeps its history), or by IP when no MAC was seen. Each scan matches hosts to **agents**: by MAC against the network interfaces in the agents' inventories (any site of the client), else by IP within the same site. A matched host is *managed*. The rest are *unmanaged* and listed with actions:

- **Ignore**: not interesting; leaves the list.
- **Mark as known**: accepted without an agent (the label printer), with a note.
- **Monitor**: start reading it over SNMP (needs credentials that worked or that you pick).
- **Deploy agent**: for hosts that look like computers, how they might take one (RDP, WinRM, SMB for Windows; SSH for Linux), from their open ports. No token is minted for you: enrollment tokens come from the site's Install agent dialog.

A host the latest scan didn't see (inside the scanned blocks) is shown as offline. First and last seen are kept.

## SNMP monitoring

`rmm-snmp` is our own client: v2c, and v3 with MD5/SHA-1/SHA-2 authentication and DES/AES-128 privacy, engine discovery and clock synchronisation. It is pure Rust and small. Read-only: no `SET`, no traps. It is tested against the RFC 3414 key-localization and NIST AES vectors, against a simulator, and against net-snmp's `snmpd` (`crates/rmm-snmp/tests/netsnmp.rs`, and the e2e).

What is read, per device, at the site's interval (300 s unless a device says otherwise; 60-3600):

- system group: `sysUpTime`, `sysName`, `sysDescr`, `sysObjectID`, `sysLocation`;
- **IF-MIB** `ifTable`/`ifXTable`: name, alias, type, speed, admin and operational status, octet counters (64-bit where the device has them), errors and discards, for at most 512 interfaces;
- **HOST-RESOURCES-MIB**: processor load, RAM and disks; **UCD-SNMP** CPU and memory where that's what the device has;
- **Printer-MIB** supplies (toner, ink, waste) for printers and unknown devices.

Counters become rates on the server from the previous reading. A 32-bit counter that wrapped once is corrected; a counter that went back (or a device that restarted) gives no rate that time. Devices are read a few at a time (8), one request in flight per site. Credentials (`net_credentials`) are per client and write-only through the API; the secret is sealed with `RMM_DATA_KEY` like the other secrets, and `rmm-server rotate-data-key` reseals it.

### What is stored

- `net_devices`: current state (`up`/`down`/`unknown`), uptime, CPU, memory, storage, supplies.
- `net_interfaces`: current state of each interface and the counters the next rate is worked out from. An interface becomes **monitored** the first time it is seen up (not loopbacks and tunnels), so unused ports don't alert and don't fill the database; it can be switched by hand.
- `net_device_metrics`, `net_interface_metrics`: raw samples for `RMM_METRICS_RAW_DAYS`, only for monitored interfaces; hourly rollups (`*_hourly`) for `RMM_METRICS_RETENTION_DAYS`, written by the housekeeping loop like the agent metrics.

A device whose designated agent is offline is not marked down: it isn't being read, which is the agent's problem and has its own alert.

## Alerts

Three new kinds of alert item, set up like any other in a policy set (Policies → Alerts), on the **designated agent's** policy set:

| Kind | Opens when |
|---|---|
| `net_down` | A device hasn't answered for `minutes`. Optionally only some device kinds. |
| `net_interface` | A monitored interface that is administratively up has been down for `minutes`. Optionally only interfaces whose name, description or alias match (`*` globs). A port someone switched off on purpose is not a fault. |
| `net_threshold` | `cpu` or `memory` at or above a percentage for `minutes`; `interface_util` (percent of the interface's speed) for `minutes`; or `supply` (toner or ink) at or below a percentage. |

The alerts are ordinary alerts (`alerts.device_id`, with `agent_id` the designated agent): severity, channels, reminders, tickets, muting by the agent's windows, webhooks, acknowledge and resolve all work. They don't count against the designated agent's **health**: migration 0033 replaces `refresh_agent_alerts` so that only an agent's own alerts feed its stored health. Alerts are evaluated whenever the agent reports a device, and again for the devices an item reaches when the item changes. Items can't exclude single devices; scope them with the item's client and site.

## API and permissions

`/api/sites/{id}/network`, `/api/network/*` and `/api/clients/{id}/network-credentials` (see `api/network.rs`). Everything is scoped to the clients the user can see; reads need no role, changes need a technician, and all changes are audited (`network.*`). Four read operations are in the public API under the `network` scope: `listNetworkDevices`, `getNetworkDevice`, `getNetworkDeviceMetrics`, `listDiscoveredDevices`. Starting scans and changing devices or credentials is dashboard-only: a key can't make an agent scan or reach credentials.

## Limits and what isn't here

- IPv4 scans only; devices may be IPv6 literals.
- ICMP needs Linux and the right to open a ping socket; on Windows and macOS discovery relies on TCP and the neighbour table (mDNS and SNMP too). Windows paths are compile-checked, not run on a Windows host.
- No traps, no SNMP `SET`, no vendor MIBs beyond the four above, no topology (LLDP/CDP) yet.
- SNMPv3 AES-192/256 (the non-standard key extensions) isn't supported.
- Only one scan at a time per agent, one poll in flight per site.
