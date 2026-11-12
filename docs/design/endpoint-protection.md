# Endpoint protection design

The design for endpoint protection (Phase 8 of [the roadmap](../ROADMAP.md)). Milestones 1-7 are built; milestone 8 is "later or never". Kept as the record of why it's built this way.

## Decisions made while building it

- **Permission sets** were built here, since Phase 7 had deferred them: roles grant defaults (read-only: `security.read`; technician: + `security.respond`; admin: all) and an admin can give a user an explicit set. Quarantine and isolation are gated on them.
- **Alerts through alert policies, not a separate `security_policies` table.** Milestone 1 only needs thresholds and notifications, which alert policies already have (scope, severity, channels, tickets). `security_policies` arrives with scheduled scans and exclusions in milestone 2.
- **No sensor process yet.** Milestone 1 only reads the platform's own products and runs their CLIs, from the agent. The separate `rmm-sensor` comes with our own scanning (milestone 2) and telemetry (milestone 3).
- **Detections the product forgets are resolved**, not deleted: Defender drops old detections from its history, and the server keeps the record.

## Goal

Goal: endpoint protection managed from the same console, so a detection becomes an alert, a ticket and a response action next to the device's live state. MSPs pay per seat for this today, and cyber insurers ask for it.

## Scope decisions

- **Manage the built-in protection first.** Microsoft Defender (Windows), ClamAV (Linux) and XProtect (macOS) already scan files. Reporting their state, triggering scans and turning findings into alerts is the cheapest useful step.
- **Run beside Defender, not instead of it.** Replacing Defender as the registered antivirus in Windows Security Center needs Microsoft Virus Initiative membership and an ELAM driver, which in practice needs an established product with independent test results. Until then we add telemetry, detection and response on top of Defender.
- **User mode before kernel mode.** Prefer the platform's supported telemetry APIs (ETW on Windows, eBPF/fanotify/audit on Linux, Endpoint Security on macOS). A custom kernel driver is a last step, only if the gaps prove to matter, because a driver fault can crash every machine it is on.
- **Not a managed detection service.** Software can't watch the console overnight. We provide the queue, context and response buttons; staffing or an MDR partner is the MSP's call.
- **No machine-learning classifier early.** It needs a labelled corpus and continual retraining. Start with hashes, signatures, YARA-style rules and behaviour rules.

## Prerequisites

- Windows agent proven on real hosts (Phase 2 to-do).
- Permission sets from Phase 7: `security.read`, `security.respond` (quarantine, isolate), `security.manage` (policies, exclusions).
- Signed content pipeline: rule and signature bundles signed like agent releases (`rmm-sign`), verified on the agent, rolled out in stages.
- Agent job buffer persisted to disk, so response actions survive a restart.
- Secrets encrypted at rest (Phase 7 vault notes). Telemetry includes command lines, which can contain credentials.

## Architecture

- **Separate sensor process** (`rmm-sensor`), supervised by the agent, so a sensor fault can't take down remote access and it can be switched off per client. Local IPC to the agent, which forwards over the existing socket.
- **Events stay on the machine by default.** Keep a local, size-limited event store and send only detections and summaries. Pull detailed history on demand during an investigation.
- **Server side:** `security_detections` (rule, severity, process and file context, state), `security_policies` (per client/site/OS, like alert and patch policies), `security_exclusions`, `quarantine_items`, `content_versions`. Detections feed the health model and open alerts; alerts already open tickets (Phase 7).
- **Tamper resistance for our own product:** protect the agent's files and service from non-admin users, report when the sensor stops, and alert on it.

## Milestones

1. **Protection status and management.** Read Defender, ClamAV and XProtect state (enabled, signature age, last scan, active threats). Start scans and signature updates from the console. Alert on disabled protection, stale signatures and detections. Show a Security tab per agent and a fleet view.
2. **File scanning.** On-demand and scheduled scans in the sensor with hash reputation and rule matching against a signed bundle. Quarantine with restore (files moved to a protected store, never deleted outright). Exclusions with an audit trail.
3. **Telemetry.** Process start, command line, parent chain, module loads, network connections, and file and registry changes of interest, from the supported platform APIs above. Local store and an on-demand query from the console.
4. **Behaviour detection.** A rule engine over the telemetry (rule format, severity, MITRE ATT&CK tags), with a starter set for common ransomware, credential-theft and persistence behaviour. Every rule ships with test cases and a measured false-positive rate on a clean-fleet baseline; new rules start in audit-only mode.
5. **Response.** Kill a process tree, quarantine a file, isolate a host from the network while keeping the management channel, collect a triage package, and roll back changes where feasible. All audited and permission-gated, available from alerts and tickets.
6. **Investigation UI.** Detection detail with a process tree and timeline, search across the fleet, and "have we seen this hash elsewhere".
7. **Prevention.** Block-on-detect for high-confidence rules only, after enough audit-mode history. Staged rollout (canary clients first) with automatic rollback if a content update raises crash or false-positive counts.
8. **Later or never:** custom kernel driver, ELAM and MVI registration, a cloud sandbox, threat-intel feed integration, ML classification, application control and device control.

## Testing

- Unit tests per rule against recorded event streams, and a replay harness so rules run in CI.
- Benign-software corpus run before every content release to catch false positives.
- Detection coverage checked against a published adversary-emulation test set in an isolated lab, never on customer machines.
- Performance budget: CPU, memory and disk I/O caps for the sensor, measured on low-end hardware.
- Content and agent updates tested for safe rollback; a bad rule must be disableable from the server without a new agent build.

## Risks and open questions

- **False positives and outages.** A bad rule or update can quarantine legitimate software fleet-wide. Staged rollout, audit-first and a kill switch are required before any blocking.
- **Liability and expectations.** Selling protection implies a promise. Marketing and contracts need to say what it does and doesn't cover.
- **Maintenance cost.** Rule upkeep never ends; decide up front whether to license a signature/threat-intel feed or maintain our own.
- **Windows first, Linux second, macOS last** matches where MSP fleets are, but macOS needs Apple entitlements and notarisation.
- **Build vs. integrate.** Some MSPs already standardise on another EDR. Keep an integration path (ingest their detections as alerts) as a parallel option.
