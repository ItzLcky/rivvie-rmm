export type Role = 'admin' | 'technician' | 'readonly';
export interface User {
	id: string; email: string; name: string; role: Role; totp_enabled: boolean; mfa_setup_required: boolean;
	/** null = every client */
	client_ids: string[] | null;
	preferences?: import('./prefs.svelte').Prefs;
	/** Effective named permissions (security.read / security.respond / security.manage). */
	permissions?: string[];
}

/** A keyset-paged list response. Pass `next`/`prev` back as `?after=`/`?before=`. */
export interface Page<T> { items: T[]; next: string | null; prev: string | null; total: number; total_exact: boolean }

export type Health = 'healthy' | 'attention' | 'unhealthy' | 'unknown';

export interface DiskUsage { mount: string; total: number; available: number }
export interface Metrics {
	ts: string; uptime_secs: number; cpu_percent: number; load_avg: [number, number, number] | null;
	mem_total: number; mem_used: number; swap_total: number; swap_used: number;
	disks: DiskUsage[]; net_rx_bytes: number; net_tx_bytes: number; process_count: number;
}

export interface AgentSummary {
	id: string; hostname: string; os_family: 'linux' | 'windows' | 'macos' | 'other'; os_name: string; os_version: string;
	arch: string; agent_version: string; online: boolean; last_seen_at: string | null; enrolled_at: string;
	site_id: string; site_name: string; client_id: string; client_name: string; last_metrics: Metrics | null;
	update_state: UpdateState | null; update_version: string | null; update_detail: string | null; update_at: string | null;
	health: Health; disk_max_pct: number; failed_jobs_24h: number; open_alerts: number;
	/** Security or critical updates missing for over a week. */
	patches_overdue: number; patches_failed: number; reboot_pending: boolean; reboot_pending_since: string | null;
	/** A maintenance window or snooze is holding its alerts back right now. */
	alerts_muted: boolean;
	/** Policy management: its device category and the policy set it uses. */
	platform?: 'workstation' | 'server'; category_id?: string; category_name?: string; policy_set_id?: string; policy_set_name?: string;
}

export type UpdateState = 'offered' | 'downloading' | 'waiting' | 'applying' | 'completed' | 'rolled_back' | 'failed';
export interface Release { platform: string; version: string; sha256: string; size: number; outdated: number }

export interface Software { name: string; version: string; publisher: string | null; source: string }
export interface Inventory {
	collected_at: string; cpu_brand: string; cpu_cores_physical: number | null; cpu_cores_logical: number; mem_total: number;
	disks: { name: string; mount: string; fs: string; kind: string; removable: boolean; total: number }[];
	network: { name: string; mac: string; addrs: string[] }[];
	software: Software[]; logged_in_users: string[];
}
export interface AgentDetail extends AgentSummary {
	kernel_version: string; machine_id: string | null; inventory: Inventory | null; inventory_at: string | null;
	/** Optional features its build supports, as of its last connection (`patch`, `desktop`). */
	capabilities: string[];
}

export interface MetricPoint {
	ts: string; cpu_percent: number; mem_used: number; mem_total: number; disk_max_pct: number; net_rx_bytes: number; net_tx_bytes: number;
}

export interface Site { id: string; client_id: string; name: string; agent_count: number; online_count: number }
export interface Client {
	id: string; name: string; created_at: string; sites: Site[];
	/** Mail from these domains is filed under this client. */
	email_domains: string[];
	/** Gets new security content first (canary ring). */
	security_canary?: boolean;
	/** null: the default SLA policy. */
	sla_policy_id?: string | null;
	/** The client portal lists this client's devices. */
	portal_devices?: boolean;
}

export type Interpreter = 'bash' | 'sh' | 'powershell' | 'cmd' | 'python';
export interface Script {
	id: string; name: string; description: string; interpreter: Interpreter; body: string; timeout_secs: number;
	/** null = MSP-wide */
	client_id: string | null; client_name: string | null;
	created_at: string; updated_at: string;
}

export type JobStatus = 'queued' | 'sent' | 'succeeded' | 'failed' | 'timed_out' | 'error' | 'cancelled' | 'lost' | 'expired';
export interface Job {
	id: string; agent_id: string; hostname: string; script_id: string | null; script_name: string | null; interpreter: Interpreter;
	status: JobStatus; exit_code: number | null; created_by_name: string | null; created_at: string; sent_at: string | null;
	finished_at: string | null; duration_ms: number | null; schedule_id: string | null; schedule_name: string | null;
}
export interface JobDetail extends Job {
	body: string; args: string[]; timeout_secs: number; stdout: string; stderr: string;
	/** Full output lengths, to pass back as since_stdout/since_stderr for the next chunk. */
	stdout_len: number; stderr_len: number;
}

export interface ClientHealth { id: string; name: string; agents: number; online: number; attention: number; unhealthy: number; failed_jobs_24h: number; open_alerts: number }
export interface Dashboard {
	agents_total: number; agents_online: number; clients: number; by_os: Record<string, number>;
	health: Partial<Record<Health, number>>; jobs_24h: Partial<Record<JobStatus, number>>;
	offline: AgentSummary[]; high_disk: AgentSummary[]; failed_jobs: Job[]; client_health: ClientHealth[];
	alerts: Partial<Record<Severity, number>>; open_alerts: Alert[];
}

export interface AuditRow { id: number; ts: string; user_name: string | null; action: string; target_type: string | null; target_id: string | null; details: Record<string, unknown> }

export interface SearchResults {
	agents: { id: string; hostname: string; os_family: string; online: boolean; client_name: string; site_name: string }[];
	clients: { id: string; name: string }[];
	sites: { id: string; name: string; client_id: string; client_name: string }[];
	scripts: { id: string; name: string; interpreter: Interpreter; client_name: string | null }[];
	tickets: { id: string; number: number; subject: string; client_name: string | null; status_name: string }[];
}

export interface Session { id: string; created_at: string; last_seen_at: string; expires_at: string; user_agent: string | null; current: boolean }

export type Severity = 'critical' | 'warning' | 'info';
export type AlertState = 'open' | 'acknowledged' | 'resolved';
export type PolicyKind = 'offline' | 'cpu' | 'memory' | 'disk' | 'service' | 'job_failed' | 'log' | 'security' | 'patch';
export type LogLevel = 'critical' | 'error' | 'warning' | 'info';

export interface Alert {
	id: string; policy_id: string | null; policy_name: string | null; agent_id: string; hostname: string; client_id: string;
	client_name: string; site_name: string; kind: PolicyKind; severity: Severity; title: string; details: Record<string, unknown>;
	occurrences: number; state: AlertState; opened_at: string; last_seen_at: string; acknowledged_at: string | null;
	acknowledged_by_name: string | null; resolved_at: string | null; resolved_by_name: string | null;
	/** cleared (condition went away), manual, policy (policy changed or deleted) */
	resolution: 'cleared' | 'manual' | 'policy' | null;
	/** Opened during a maintenance window or snooze: nobody was notified (yet). */
	suppressed: boolean;
}
export interface Delivery {
	id: number; channel_name: string; channel_kind: ChannelKind; event: 'opened' | 'resolved' | 'test';
	status: 'pending' | 'sent' | 'failed'; attempts: number; last_error: string | null; created_at: string; sent_at: string | null;
}
export interface LogEvent {
	id: number; ts: string; received_at?: string; level: LogLevel; source: string; event_id: number | null; message: string;
	policy_id?: string | null; policy_name: string | null; alert_id?: string | null;
}
export interface AlertDetail extends Alert { notifications: Delivery[]; log_events: LogEvent[]; ticket: { id: string; number: number } | null }

/** A maintenance window (weekly) or snooze (one-off) holding alerts back. */
export interface Mute {
	id: string; client_id: string | null; site_id: string | null; agent_id: string | null; owner_client_id: string; target_name: string;
	starts_at: string | null; ends_at: string | null; days: number[] | null; start_time: string | null; minutes: number | null; tz: string;
	reason: string; created_by_name: string | null; created_at: string; active: boolean; ended: boolean;
}

export interface Process {
	pid: number; ppid: number | null; name: string; exe: string | null; cmd: string | null; user: string | null;
	cpu: number; mem: number; started_at: string | null; protected: boolean;
}
export interface DirEntry { name: string; path: string; dir: boolean; symlink: boolean; size: number; modified: string | null; error: string | null }
export interface DirListing { path: string; parent: string | null; entries: DirEntry[]; truncated: boolean }

export type ChannelKind = 'email' | 'webhook' | 'slack' | 'teams';
export interface Channel {
	id: string; name: string; kind: ChannelKind; enabled: boolean; policies: number; created_at: string; has_secret: boolean;
	/** Admins only. */
	config?: { to?: string[]; url?: string };
}
export interface DeliveryRow extends Delivery { channel_id: string; alert_id: string | null; alert_title: string | null; hostname: string | null; next_attempt_at: string }
export interface Smtp { host: string; port: number; security: 'starttls' | 'tls' | 'none'; username: string; password_set: boolean; from: string }

/** A scheduled script (a `schedule` item of a policy set), read-only here: it's edited in its set. */
export interface Schedule {
	id: string; name: string; set_id: string; set_name: string; script_id: string; script_name: string; interpreter: Interpreter; client_id: string | null; client_name: string | null;
	site_id: string | null; site_name: string | null; cron: string; timezone: string; args: string[];
	/** Devices it runs on now. */
	agents: number;
	timeout_secs: number | null; retain_days: number; enabled: boolean; next_run_at: string | null; last_run_at: string | null;
	last_run: Partial<Record<JobStatus, number>>; created_by_name: string | null; created_at: string; updated_at: string;
}

export type ServiceState = 'running' | 'stopped' | 'failed' | 'starting' | 'stopping' | 'paused' | 'unknown';
export interface ServiceInfo { name: string; display_name: string; state: ServiceState; start_mode: 'auto' | 'manual' | 'disabled' | 'unknown' }
export interface AgentServices { services: ServiceInfo[] | null; services_at: string | null; alerting: string[] }

// Patch management
export type PatchSeverity = 'critical' | 'important' | 'moderate' | 'low' | 'unspecified';
export type PatchCategory = 'security' | 'critical' | 'definition' | 'driver' | 'feature' | 'rollup' | 'update' | 'other';
export type PatchState = 'missing' | 'installing' | 'installed' | 'failed';
export type Approval = 'pending' | 'approved' | 'declined';
export type RebootPolicy = 'never' | 'if_required' | 'always';
export type RunStatus = 'queued' | 'sent' | 'succeeded' | 'partial' | 'failed' | 'lost' | 'expired' | 'cancelled';

/** One update across the fleet (`GET /patches`). */
export interface UpdateGroup {
	update_id: string; title: string; kb: string | null; severity: PatchSeverity | null; category: PatchCategory; size: number | null;
	requires_reboot: boolean; missing: number; installed: number; failed: number; installing: number;
	approved: number; pending: number; declined: number; first_seen_at: string;
}
export interface UpdateAgent {
	agent_id: string; hostname: string; online: boolean; os_family: AgentSummary['os_family']; client_id: string; client_name: string;
	site_name: string; state: PatchState; approval: Approval; approval_manual: boolean; approved_by_name: string | null;
	approved_at: string | null; version: string | null; current_version: string | null; first_seen_at: string;
	installed_at: string | null; last_error: string | null; fail_count: number;
}
export interface AgentPatch {
	update_id: string; title: string; kb: string | null; severity: PatchSeverity | null; category: PatchCategory; size: number | null;
	requires_reboot: boolean; version: string | null; current_version: string | null; state: PatchState; approval: Approval;
	approval_manual: boolean; approved_by_name: string | null; approved_at: string | null; first_seen_at: string;
	installed_at: string | null; last_error: string | null; fail_count: number; deferred_until: string | null;
}
/** The patch policy as it applies to one agent (its set's merged patch item). */
export interface AgentPatchPolicy {
	/** The patch item, its agent's set, and that set's name. */
	id: string; set_id: string; source: string;
	auto_approve_severities: PatchSeverity[]; auto_approve_categories: PatchCategory[]; deferral_days: number; auto_install: boolean;
	reboot_policy: RebootPolicy;
	/** The policy has a window of its own; otherwise automatic installs use the site's. */
	own_window: boolean;
	window: { days: number[] | null; start: string | null; minutes: number | null; tz: string; open_now: boolean; next_start: string | null } | null;
}
export interface MaintenanceWindow {
	site_id: string; site_name: string; client_id: string; client_name: string; days: number[] | null; start: string | null;
	minutes: number | null; tz: string; open_now: boolean; next_start: string | null; agents: number;
}
export interface PatchRun {
	id: string; agent_id: string; hostname: string; client_id: string; client_name: string; trigger: 'manual' | 'policy';
	created_by_name: string | null; status: RunStatus; stage: string | null; progress: string | null; percent: number | null;
	error: string | null; updates: number; succeeded: number; reboot_policy: RebootPolicy; reboot_required: boolean; rebooting: boolean;
	created_at: string; sent_at: string | null; finished_at: string | null; duration_ms: number | null;
}
export interface PatchRunDetail extends PatchRun {
	output: string;
	items: { update_id: string; title: string | null; kb: string | null; severity: PatchSeverity | null; ok: boolean | null; message: string | null }[];
}
export interface AgentPatches {
	status: {
		supported: boolean; online: boolean; os_family: string; provider: string | null; all_or_nothing: boolean; scanned_at: string | null;
		scan_requested_at: string | null; scan_error: string | null; reboot_pending: boolean;
	};
	policy: AgentPatchPolicy | null; window: MaintenanceWindow; patches: AgentPatch[]; runs: PatchRun[];
}
export interface ComplianceRow {
	id: string; name: string; client_id: string | null; agents: number; supported: number; scanned: number; compliant: number;
	missing: number; agents_missing_security: number; failed: number; reboot_pending: number; scan_errors: number;
	installed_30d: number; oldest_scan: string | null;
}
export interface Compliance {
	by: 'client' | 'site';
	totals: Omit<ComplianceRow, 'id' | 'name' | 'client_id' | 'oldest_scan'>;
	rows: ComplianceRow[];
}

// --- Service desk ------------------------------------------------------------------------------

export type Priority = 1 | 2 | 3 | 4;
export type StatusCategory = 'new' | 'open' | 'waiting_client' | 'waiting_vendor' | 'resolved' | 'closed';
export type TicketSource = 'dashboard' | 'email' | 'alert' | 'portal' | 'api';
export interface BoardStatus { id: string; name: string; category: StatusCategory; position: number }
export interface Board {
	id: string; name: string; description: string; position: number; statuses: BoardStatus[]; open_tickets: number;
	default_team_id: string | null; notify_channel_ids: string[];
}
export interface Team { id: string; name: string; member_ids: string[]; open_tickets: number }
export interface TicketType { id: string; name: string; position: number }
export interface Technician { id: string; name: string; email: string; client_ids: string[] | null }
export interface TicketMeta { boards: Board[]; types: TicketType[]; technicians: Technician[]; teams: Team[] }

export interface Ticket {
	id: string; number: number; subject: string; client_id: string | null; client_name: string | null; site_id: string | null; site_name: string | null;
	contact_id: string | null; contact_name: string | null; contact_email: string | null; board_id: string; board_name: string;
	status_id: string; status_name: string; status_category: StatusCategory; type_id: string | null; type_name: string | null;
	priority: Priority; impact: 1 | 2 | 3 | null; urgency: 1 | 2 | 3 | null; source: TicketSource; assignee_id: string | null; assignee_name: string | null;
	requester_name: string; requester_email: string; created_at: string; updated_at: string; first_response_at: string | null;
	resolved_at: string | null; closed_at: string | null; merged_into: string | null; merged_into_number: number | null;
	alert_policy_id: string | null; alert_reopens: number; agent_count: number;
	team_id: string | null; team_name: string | null;
	sla_policy_id: string | null; sla_policy_name: string | null; respond_by: string | null; update_by: string | null; resolve_by: string | null;
	/** Waiting on the client (or resolved): the clock is stopped. */
	sla_paused: boolean; sla_warned: SlaTarget[]; sla_breached: SlaTarget[];
	/** The next deadline still running. */
	sla_due: string | null;
	csat_rating: 'good' | 'bad' | null;
}
export type SlaTarget = 'respond' | 'update' | 'resolve';
export type TicketEventKind = 'created' | 'reply' | 'message' | 'note' | 'change' | 'alert' | 'job' | 'session' | 'merge' | 'agent' | 'sla' | 'split' | 'csat' | 'time' | 'doc';
export interface TicketEvent {
	id: number; kind: TicketEventKind; public: boolean; author_id: string | null; author_contact_id: string | null;
	author_kind: 'user' | 'contact' | 'system'; author_name: string; body: string; data: Record<string, unknown>; created_at: string;
	email_status: 'pending' | 'sent' | 'failed' | null; email_error: string | null; email_to: string[] | null;
}
/** A documentation page linked to a ticket. `category` is "" when there is none. */
export interface TicketDoc { id: string; title: string; category: string; updated_at: string; updated_by_name: string | null }
export interface TicketAttachment { id: string; event_id: number | null; name: string; content_type: string; size: number; uploaded_by_name: string | null; created_at: string }
export interface TicketAgent extends AgentSummary {
	capabilities: string[]; reboot_pending: boolean; missing_patches: number;
	alerts: { id: string; title: string; severity: Severity; opened_at: string }[];
}
export interface TicketDetail extends Ticket {
	events: TicketEvent[]; attachments: TicketAttachment[]; agents: TicketAgent[]; statuses: BoardStatus[];
	/** Linked documentation pages, by title. */
	docs: TicketDoc[];
	/** Where a public reply is emailed, if anywhere. */
	reply_to: string | null;
	csat: { email: string; sent_at: string; rating: 'good' | 'bad' | null; comment: string; answered_at: string | null } | null;
}
export interface TicketSummary { open: number; mine: number; unassigned: number; triage: number; waiting: number; team: number; breached: number }

export interface CannedResponse {
	id: string; name: string; body: string; kind: 'reply' | 'note'; status_category: StatusCategory | null; priority: Priority | null;
	assign: 'me' | 'none' | null; owner_id: string | null; updated_at: string;
}
export interface SlaTargets { priority: Priority; respond_mins: number | null; update_mins: number | null; resolve_mins: number | null }
export interface SlaPolicy {
	id: string; name: string; calendar_id: string | null; calendar_name: string | null; is_default: boolean; channel_ids: string[];
	notify_assignee: boolean; targets: SlaTargets[]; clients: number; open_tickets: number;
}
/** Monday first; [start, end] minutes from local midnight. */
export type WeekHours = [number, number][][];
export interface BusinessCalendar { id: string; name: string; timezone: string; hours: WeekHours; holidays: { day: string; name: string }[]; policies: number }
export interface KbArticle {
	id: string; title: string; category: string; public: boolean; client_id: string | null; client_name: string | null; body?: string | null;
	excerpt: string; updated_by_name: string | null; created_at: string; updated_at: string;
}
export interface DeskSettings { portal_board_id: string | null; portal_welcome: string; csat_enabled: boolean }

export interface Contact {
	id: string; client_id: string; client_name: string; site_id: string | null; site_name: string | null; name: string; email: string;
	phone: string; job_title: string; notes: string; is_primary: boolean; portal_enabled: boolean; open_tickets: number;
	portal_all_tickets: boolean; portal_last_login_at: string | null; is_billing: boolean;
	created_at: string; updated_at: string;
}

export interface Mailbox {
	id: string; name: string; address: string; kind: 'imap' | 'webhook' | 'graph'; imap_host: string; imap_port: number; imap_security: 'tls' | 'none';
	imap_username: string; has_password: boolean; imap_folder: string; board_id: string; board_name: string; auto_reply: boolean;
	enabled: boolean; last_polled_at: string | null; last_error: string | null; received_24h: number; created_at: string;
	graph_tenant: string; graph_client_id: string; has_graph_secret: boolean; graph_send: boolean;
	/** Only right after creating a webhook mailbox (or rotating its token). */
	webhook_url?: string;
}
export interface InboundMail {
	id: string; mailbox_name: string | null; from_addr: string; subject: string; status: 'received' | 'ignored';
	ignored_reason: string | null; ticket_id: string | null; ticket_number: number | null; created_at: string;
}

// Endpoint protection (Phase 8)
/** threats: an active detection; unprotected: no product enabled; at_risk: see `SecurityRisk`. */
export type ProtectionState = 'threats' | 'unprotected' | 'at_risk' | 'unknown' | 'protected';
export type ProductKind = 'defender' | 'clamav' | 'xprotect' | 'rmm' | 'other';
export type SecurityAction = 'quick_scan' | 'full_scan' | 'update_signatures';
/**
 * Why an agent is at risk: no enabled product scans in real time; no product has current
 * signatures; our database is older than the security policy allows; our real-time protection is
 * wanted and not on (Linux only: elsewhere it doesn't exist yet).
 */
export type SecurityRisk = 'realtime_off' | 'signatures' | 'database' | 'sensor_realtime';
/** The signature database an agent runs, as the server has it. */
export interface AgentDatabase { version: string; built_at: string; stage: ContentStage; hashes: number; yara_rules: number; size: number }
export type ThreatSeverity = 'severe' | 'high' | 'moderate' | 'low' | 'unknown';
export type ThreatStatus = 'active' | 'quarantined' | 'removed' | 'blocked' | 'allowed' | 'unknown';
export type SecurityActionStatus = 'sent' | 'running' | 'succeeded' | 'failed' | 'lost';
export interface SecurityProduct {
	kind: ProductKind; name: string; version: string | null; enabled: boolean | null; realtime: boolean | null;
	signature_version: string | null; signatures_updated_at: string | null;
	/** Security Center's verdict, for products that don't give a date. */
	signatures_current: boolean | null;
	last_quick_scan_at: string | null; last_full_scan_at: string | null; tamper_protection: boolean | null;
	actions: SecurityAction[]; detail: string | null;
}
export interface SecurityDetection {
	id: string; agent_id: string; hostname: string; client_id: string; client_name: string; site_name: string;
	product: ProductKind; name: string; severity: ThreatSeverity; status: ThreatStatus; resources: string[];
	process: string | null; username: string | null; detected_at: string | null; first_seen_at: string; last_seen_at: string;
	resolved_at: string | null;
	source: DetectionSource; rule_id: string | null; mitre: string[];
	/** Recorded by a rule in audit mode: not acted on, not alerted. */
	audit: boolean; action_taken: string | null; sha256: string | null; verdict: Verdict | null;
	/** How a file detection was found (our sensor); null for behaviour and other products. */
	found_by?: FoundBy | null;
	/** The program was refused before it ran. */
	denied?: boolean;
}
export type FoundBy = 'on_exec' | 'on_write' | 'scan' | 'reputation';
export type RealtimeMode = 'off' | 'audit' | 'block';
export interface SecurityActionRow {
	id: string; product: ProductKind; action: SecurityAction | ResponseActionName; status: SecurityActionStatus; message: string | null;
	created_by_name: string | null; created_at: string; started_at: string | null; finished_at: string | null;
	params: Record<string, unknown>; result: Record<string, unknown> | null; has_download: boolean;
}
export interface AgentSecurity {
	supported: boolean; online: boolean; state: ProtectionState; reported_at: string | null; error: string | null;
	products: SecurityProduct[]; detections: SecurityDetection[]; actions: SecurityActionRow[];
	sensor_supported: boolean; sensor: SensorStatus | null; sensor_at: string | null; content_version: string | null;
	isolated: boolean; policy: SensorPolicy; quarantine: QuarantineRow[];
	risks: SecurityRisk[]; database: AgentDatabase | null;
	/** The security policy's limit on the database's age, hours (0: none). */
	database_max_age_hours: number;
}
export interface SecurityAgentRow {
	id: string; hostname: string; online: boolean; os_family: AgentSummary['os_family']; client_id: string; client_name: string;
	site_id: string; site_name: string; state: ProtectionState; security_at: string | null; security_error: string | null;
	products: { kind: ProductKind; name: string; enabled: boolean | null; realtime: boolean | null }[];
	signatures_updated_at: string | null; last_scan_at: string | null; active_threats: number; running_action: SecurityAction | null;
	isolated: boolean; sensor: SensorStatus | null; content_version: string | null;
	risks: SecurityRisk[]; database_version: string | null; database_built_at: string | null; database_max_age_hours: number;
	/** The policy's prevention: without it real-time Block denies nothing. */
	prevention: boolean;
}
export interface SecuritySummary {
	agents: Record<ProtectionState, number>; active_threats: number; detections_7d: number; actions_running: number;
}

// Our sensor, response and investigation (Phase 8, milestones 2-7)
export type DetectionSource = 'product' | 'file' | 'behaviour';
export type Verdict = 'true_positive' | 'false_positive' | 'benign';
export type RuleMode = 'disabled' | 'audit' | 'alert' | 'block';
export type ExclusionKind = 'path' | 'sha256' | 'rule' | 'process';
export type EventKind = 'process' | 'network' | 'file' | 'registry' | 'module';
export type ContentStage = 'canary' | 'general' | 'rolled_back' | 'retired';
export type QuarantineState = 'quarantined' | 'restored' | 'deleted' | 'gone';
export type ResponseActionName =
	| 'kill_process' | 'quarantine_file' | 'restore_file' | 'delete_quarantined' | 'isolate' | 'release' | 'collect_triage' | 'scan_path';
export type ResponseAction =
	| { type: 'kill_process'; pid: number; tree: boolean }
	| { type: 'quarantine_file'; path: string }
	| { type: 'restore_file'; id: string }
	| { type: 'delete_quarantined'; id: string }
	| { type: 'isolate'; allow: string[] }
	| { type: 'release' }
	| { type: 'collect_triage' }
	| { type: 'scan_path'; path: string };

export interface SensorPolicy {
	enabled: boolean; quick_scan_hours: number; full_scan_days: number; auto_quarantine: boolean; prevention: boolean;
	telemetry_mb: number; canaries: boolean; exclusions: { kind: ExclusionKind; value: string }[]; rule_modes: [string, RuleMode][];
	realtime?: RealtimeMode; scan_on_write?: boolean; archive_depth?: number; reputation?: boolean;
}
/** On-access protection as the sensor runs it. */
export interface RealtimeHealth {
	mode: RealtimeMode;
	/** on | off (the policy) | unavailable (see error; programs are then scanned just after they start) */
	state: 'on' | 'off' | 'unavailable';
	mechanism: 'fanotify' | 'scan-after-start';
	error: string | null; scan_on_write: boolean; filesystems: number;
	decisions: number; denied: number; cache_hits: number; timeouts: number; overloaded: number;
	write_scans: number; write_dropped: number;
	/** Decision time over the last health interval, microseconds. */
	p50_us: number; p99_us: number;
}
export interface SensorHealth {
	events_total: number; events_per_min: number; store_bytes: number; cpu_percent: number; rss_bytes: number; rules: number;
	/** [collector, mechanism] */
	collectors: [string, string][];
	canaries: number; last_scan: string | null;
	database_version?: string | null; yara_rules?: number; hash_signatures?: number; files_scanned?: number; cache_hits?: number;
	realtime?: RealtimeHealth | null;
}
export interface SensorStatus {
	enabled: boolean; running: boolean; restarts: number; content_version: string | null; error: string | null; isolated: boolean;
	database_version?: string | null;
	health: SensorHealth | null;
}
export interface Proc {
	pid: number; ppid: number; name: string; exe?: string; command_line: string; user?: string; sha256?: string; started_at?: string;
}
export interface TelemetryEvent {
	seq: number; ts: string; kind: EventKind; action: string; process?: Proc; parent?: Proc;
	file?: { path: string; old_path?: string; sha256?: string };
	network?: { protocol: string; local_addr: string; local_port: number; remote_addr: string; remote_port: number };
	registry?: { key: string; value: string; data?: string };
	module?: { name: string; path?: string };
}
export interface TelemetryResult { events: TelemetryEvent[]; truncated: boolean; error: string | null }
export interface QuarantineRow {
	id: string; agent_id: string; hostname: string; client_id: string; client_name: string; path: string; sha256: string; size: number;
	reason: string | null; quarantined_at: string; state: QuarantineState; updated_at: string;
}
/** `how`: comma-separated ran, detected, quarantined. */
export interface PrevalenceRow { agent_id: string; hostname: string; client_name: string; first_seen: string; how: string; path?: string | null }
export interface ReputationEntry { name: string; severity: ThreatSeverity; source: string; added_at: string }
/** GET /security/prevalence?sha256= (counts only the user's clients). */
export interface Prevalence { sha256: string; agents: PrevalenceRow[]; seen_on: number; first_seen: string | null; known: ReputationEntry[] }
export interface DetectionRule {
	id: string; name: string; description: string; kind: 'file' | 'behaviour'; event: EventKind | null; severity: ThreatSeverity;
	confidence: 'low' | 'medium' | 'high'; mode: RuleMode; mitre: string[]; digest?: string | null;
}
export interface DetectionDetail extends SecurityDetection {
	os_family: AgentSummary['os_family']; online: boolean; isolated: boolean; context: TelemetryEvent[]; context_unavailable: boolean;
	content_version: string | null; notes: string | null; verdict_by_name: string | null; verdict_at: string | null; quarantine_id: string | null;
	database_version?: string | null; part?: string | null;
	prevalence: PrevalenceRow[]; seen_on?: number; first_seen?: string | null; reputation?: ReputationEntry[];
	actions: SecurityActionRow[]; alert: { id: string; title: string; state: string } | null; rule: DetectionRule | null;
}
export interface HuntResult {
	hits: { agent_id: string; hostname: string; client_name: string; events: TelemetryEvent[]; truncated: boolean }[];
	searched: number; offline: number; errors: { agent_id: string; hostname: string; error: string }[];
}
export interface ExclusionRow {
	id: string; client_id: string | null; client_name: string | null; kind: ExclusionKind; value: string; comment: string;
	created_by_name: string | null; created_at: string;
}
export interface RuleRow extends DetectionRule {
	override_mode: RuleMode | null; override_reason: string | null; effective_mode: RuleMode; first_seen: string | null; stage: string;
	hits_7d: number; audit_hits_7d: number; agents_30d: number; true_positives: number; false_positives: number; fp_rate: number | null;
	can_block: boolean; block_blocker: string | null;
}
export interface ContentVersion {
	id: string; version: string; sha256: string; description: string; rule_count: number; hashes: number; stage: ContentStage;
	stage_reason: string | null; uploaded_by_name: string | null; uploaded_at: string; stage_changed_at: string; agents: number;
}
export interface ContentOverview { versions: ContentVersion[]; canary_clients: number; soak_minutes: number; verifies_signatures: boolean }
/** A signature database (hashes and YARA rules, built and signed by `rmm-sign build-db`). */
export interface SignatureDatabase {
	id: string; version: string; sha256: string; size: number; description: string; hashes: number; yara_rules: number; rule_count: number;
	/** What `build-db` imported. `kind`: sha256-list, yara, clamav-hdb, clamav-hsb. */
	sources: { name: string; kind: string; entries: number }[];
	built_at: string; stage: ContentStage; stage_reason: string | null;
	/** False once pruned from storage: it can't be rolled out again. */
	stored: boolean;
	uploaded_by_name: string | null; uploaded_at: string; stage_changed_at: string; agents: number;
}
export interface DatabaseOverview { versions: SignatureDatabase[]; soak_minutes: number; verifies_signatures: boolean }
/** A program that ran on few machines recently and nothing knows: a hunting lead. */
export interface RareProgram {
	sha256: string; seen_on: number; first_seen: string;
	agents: { agent_id: string; hostname: string; client_name: string; path: string | null }[];
}
/** What the server's reputation set holds: `db:<version>` (the newest database) or `list:<name>`. */
export interface ReputationSource { source: string; hashes: number; added_at: string }
