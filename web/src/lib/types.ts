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
	health: Health; disk_max_pct: number; failed_jobs_24h: number;
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
	finished_at: string | null; duration_ms: number | null;
}
export interface JobDetail extends Job {
	body: string; args: string[]; timeout_secs: number; stdout: string; stderr: string;
	/** Full output lengths, to pass back as since_stdout/since_stderr for the next chunk. */
	stdout_len: number; stderr_len: number;
}

export interface ClientHealth { id: string; name: string; agents: number; online: number; attention: number; unhealthy: number; failed_jobs_24h: number }
export interface Dashboard {
	agents_total: number; agents_online: number; clients: number; by_os: Record<string, number>;
	health: Partial<Record<Health, number>>; jobs_24h: Partial<Record<JobStatus, number>>;
	offline: AgentSummary[]; high_disk: AgentSummary[]; failed_jobs: Job[]; client_health: ClientHealth[];
}

export interface AuditRow { id: number; ts: string; user_name: string | null; action: string; target_type: string | null; target_id: string | null; details: Record<string, unknown> }

export interface SearchResults {
	agents: { id: string; hostname: string; os_family: string; online: boolean; client_name: string; site_name: string }[];
	clients: { id: string; name: string }[];
	sites: { id: string; name: string; client_id: string; client_name: string }[];
	scripts: { id: string; name: string; interpreter: Interpreter; client_name: string | null }[];
}

export interface Session { id: string; created_at: string; last_seen_at: string; expires_at: string; user_agent: string | null; current: boolean }

// Patch management
export type Severity = 'critical' | 'important' | 'moderate' | 'low' | 'unspecified';
export type PatchCategory = 'security' | 'critical' | 'definition' | 'driver' | 'feature' | 'rollup' | 'update' | 'other';
export type PatchState = 'missing' | 'installing' | 'installed' | 'failed';
export type Approval = 'pending' | 'approved' | 'declined';
export type RebootPolicy = 'never' | 'if_required' | 'always';
export type RunStatus = 'queued' | 'sent' | 'succeeded' | 'partial' | 'failed' | 'lost' | 'expired' | 'cancelled';

/** One update across the fleet (`GET /patches`). */
export interface UpdateGroup {
	update_id: string; title: string; kb: string | null; severity: Severity | null; category: PatchCategory; size: number | null;
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
	update_id: string; title: string; kb: string | null; severity: Severity | null; category: PatchCategory; size: number | null;
	requires_reboot: boolean; version: string | null; current_version: string | null; state: PatchState; approval: Approval;
	approval_manual: boolean; approved_by_name: string | null; approved_at: string | null; first_seen_at: string;
	installed_at: string | null; last_error: string | null; fail_count: number; deferred_until: string | null;
}
export interface PatchPolicy {
	id: string; client_id: string | null; site_id: string | null; client_name: string | null; site_name: string | null;
	auto_approve_severities: Severity[]; auto_approve_categories: PatchCategory[]; deferral_days: number; auto_install: boolean;
	reboot_policy: RebootPolicy; updated_by_name: string | null; updated_at: string; agents: number;
	source?: 'site' | 'client' | 'global' | null;
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
	items: { update_id: string; title: string | null; kb: string | null; severity: Severity | null; ok: boolean | null; message: string | null }[];
}
export interface AgentPatches {
	status: {
		supported: boolean; online: boolean; os_family: string; provider: string | null; all_or_nothing: boolean; scanned_at: string | null;
		scan_requested_at: string | null; scan_error: string | null; reboot_pending: boolean;
	};
	policy: PatchPolicy | null; window: MaintenanceWindow; patches: AgentPatch[]; runs: PatchRun[];
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
