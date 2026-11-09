export type Role = 'admin' | 'technician' | 'readonly';
export interface User {
	id: string; email: string; name: string; role: Role; totp_enabled: boolean; mfa_setup_required: boolean;
	/** null = every client */
	client_ids: string[] | null;
	preferences?: import('./prefs.svelte').Prefs;
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
}

export interface MetricPoint {
	ts: string; cpu_percent: number; mem_used: number; mem_total: number; disk_max_pct: number; net_rx_bytes: number; net_tx_bytes: number;
}

export interface Site { id: string; client_id: string; name: string; agent_count: number; online_count: number }
export interface Client { id: string; name: string; created_at: string; sites: Site[] }

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
}

export interface Session { id: string; created_at: string; last_seen_at: string; expires_at: string; user_agent: string | null; current: boolean }

export type Severity = 'critical' | 'warning' | 'info';
export type AlertState = 'open' | 'acknowledged' | 'resolved';
export type PolicyKind = 'offline' | 'cpu' | 'memory' | 'disk' | 'service' | 'job_failed' | 'log';
export type LogLevel = 'critical' | 'error' | 'warning' | 'info';

export interface Alert {
	id: string; policy_id: string | null; policy_name: string | null; agent_id: string; hostname: string; client_id: string;
	client_name: string; site_name: string; kind: PolicyKind; severity: Severity; title: string; details: Record<string, unknown>;
	occurrences: number; state: AlertState; opened_at: string; last_seen_at: string; acknowledged_at: string | null;
	acknowledged_by_name: string | null; resolved_at: string | null; resolved_by_name: string | null;
	/** cleared (condition went away), manual, policy (policy changed or deleted) */
	resolution: 'cleared' | 'manual' | 'policy' | null;
}
export interface Delivery {
	id: number; channel_name: string; channel_kind: ChannelKind; event: 'opened' | 'resolved' | 'test';
	status: 'pending' | 'sent' | 'failed'; attempts: number; last_error: string | null; created_at: string; sent_at: string | null;
}
export interface LogEvent {
	id: number; ts: string; received_at?: string; level: LogLevel; source: string; event_id: number | null; message: string;
	policy_id?: string | null; policy_name: string | null; alert_id?: string | null;
}
export interface AlertDetail extends Alert { notifications: Delivery[]; log_events: LogEvent[] }

export interface Policy {
	id: string; name: string; kind: PolicyKind; params: Record<string, unknown>; severity: Severity;
	client_id: string | null; client_name: string | null; site_id: string | null; site_name: string | null; os_family: 'linux' | 'windows' | 'macos' | null;
	channel_ids: string[]; notify_resolved: boolean; enabled: boolean; open_alerts: number; created_at: string; updated_at: string;
}

export type ChannelKind = 'email' | 'webhook' | 'slack' | 'teams';
export interface Channel {
	id: string; name: string; kind: ChannelKind; enabled: boolean; policies: number; created_at: string; has_secret: boolean;
	/** Admins only. */
	config?: { to?: string[]; url?: string };
}
export interface DeliveryRow extends Delivery { channel_id: string; alert_id: string | null; alert_title: string | null; hostname: string | null; next_attempt_at: string }
export interface Smtp { host: string; port: number; security: 'starttls' | 'tls' | 'none'; username: string; password_set: boolean; from: string }

export interface Schedule {
	id: string; name: string; script_id: string; script_name: string; interpreter: Interpreter; client_id: string | null; client_name: string | null;
	site_id: string | null; site_name: string | null; os_family: 'linux' | 'windows' | 'macos' | null; cron: string; timezone: string; args: string[];
	timeout_secs: number | null; retain_days: number; enabled: boolean; next_run_at: string | null; last_run_at: string | null;
	last_run: Partial<Record<JobStatus, number>>; created_by_name: string | null; created_at: string; updated_at: string;
}

export type ServiceState = 'running' | 'stopped' | 'failed' | 'starting' | 'stopping' | 'paused' | 'unknown';
export interface ServiceInfo { name: string; display_name: string; state: ServiceState; start_mode: 'auto' | 'manual' | 'disabled' | 'unknown' }
export interface AgentServices { services: ServiceInfo[] | null; services_at: string | null; alerting: string[] }
