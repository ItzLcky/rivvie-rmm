# Wake-on-LAN

Design record, 2026-11-24. Status: built (parity plan C3). Migration `0043_wol.sql`.

## What it does

A technician wakes an offline device (its page's **Wake** button), or many (the **Wake** bulk action on `/agents`). A patch policy can also wake devices before their install window (`wake_before_minutes`). The packets are sent by another agent of the same site that is online: the server never sends anything onto a customer's LAN itself.

Out of scope: waking discovered (unmanaged) devices; configuring BIOS or NIC wake settings (a library script does that); waking before software-policy windows.

## Protocol

Capability `wol` (`rmm_proto::net::WOL_CAPABILITY`), so an old agent is never asked.

- `ServerMsg::WakeOnLan { request_id, targets: Vec<WolTarget { mac, last_ip }> }`, at most `MAX_WOL_TARGETS` (512) targets.
- `AgentMsg::WakeOnLanResult { request_id, sent, error }`: how many targets had at least one packet go out.

`last_ip` holds the target interface's last addresses as the inventory reports them (`10.0.0.5/24`); the plan named a single address, but the inventory has a list, so the list goes over the wire (`#[serde(default)]`).

## Agent (`rmm-agent/src/net/wol.rs`)

The magic packet is `FF` × 6, then the MAC 16 times (102 bytes). For each target it goes to UDP ports 9 and 7 of:

1. the directed broadcast of every IPv4 interface whose subnet holds one of the target's last addresses,
2. the directed broadcast of every other interface (not loopback, not /31 or /32),
3. `255.255.255.255`,

three times, 100 ms apart. Send errors on single interfaces are ignored (some refuse broadcasts); if nothing at all could be sent the answer carries an error. `RMM_WOL_FAKE=<addr:port>` sends every packet to that address instead (the e2e test points it at a UDP socket).

## Server (`rmm-server/src/wol.rs`)

`wake(st, agent_ids, by) -> Vec<Woken>`; each device gets one outcome:

| Outcome | Meaning |
|---|---|
| `sent` | the sender said the packets went out |
| `no_mac` | the inventory has no usable MAC |
| `no_sender` | no online agent of the site can send (or the sender failed, with `error`) |
| `online` | nothing to do |

- **MACs** come from `agents.inventory.network[]`. Skipped: loopback and container interfaces by name (`lo`, `docker*`, `veth*`, `virbr*`), all-zero, broadcast and multicast addresses, and the OUI prefixes of virtual adapters (VMware, VirtualBox, Hyper-V, QEMU/KVM, Xen, Parallels, Docker's `02:42`). Waking a VM's virtual NIC wakes nothing.
- **Sender:** the site's designated network agent (`site_network.agent_id`) when it is online and capable; else an online capable agent of the site on the same subnet as one of the target's addresses; else any online capable agent of the site. One request per sender, sent in parallel; the server waits up to 15 s for each answer.
- `agents.wol_sent_at` (0043) is set for devices packets went out for.
- Pending answers are kept in `wol.rs` itself rather than in the hub, so `hub.rs` is unchanged.

### Before a patch window

`PatchConfig.wake_before_minutes: Option<i32>` (0-60, `#[serde(default)]`, overridable per set; no migration, policy configs are JSON). In `patches::scheduler_tick` (every minute), `wake_before_window` picks offline devices that:

- install automatically (`auto_install`) and have an install window with days (a window that is always open has no "before"),
- have at least one eligible approved update (the same `ELIGIBLE` condition as automatic installs),
- whose window opens within `wake_before_minutes` or is open now,
- and whose `wol_sent_at` is unset or older than 12 hours.

Every picked device gets `wol_sent_at` set whatever the outcome, so one with no MAC or no sender also waits 12 hours.

## API

- `POST /agents/{id}/wake` and `POST /agents/wake {agent_ids}` (1-5,000, all visible or 404). Technicians and admins. The answer has `results` (one per device), counts per outcome, and for the single call `outcome`.
- Audit `agent.wake` (per device for the single call; counts for the bulk call).
- Public API: `wakeAgent` and `wakeAgents`, group `agents`, write keys.

## Tests

- Unit (agent): the packet bytes; destination order (target subnet first); packets reach the fake address and a bad MAC is skipped.
- Unit (server): the MAC filter; targets from an inventory; the sender choice.
- e2e (`network` section, `wake_on_lan`): B (offline, inventory written by the test) is woken through agent A and the UDP sink gets B's magic packet at least three times; waking an online agent says `online`; the bulk call reports `sent`, `no_sender` (a site with nobody online) and `no_mac`; an invisible id is 404; `wake_before_minutes` 61 is refused; with an approved update and a window opening in ten minutes, the patch scheduler wakes B once and not again on the next tick.

## Not proven here

An actual machine waking up, and switches or routers that drop directed broadcasts (most do across VLANs; the designated agent should sit on the devices' VLAN). Listed in [windows-testing.md](windows-testing.md) and the roadmap's block 1.
