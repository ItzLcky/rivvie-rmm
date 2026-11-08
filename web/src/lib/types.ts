export type Role = 'admin' | 'technician' | 'readonly';
export interface User { id: string; email: string; name: string; role: Role; totp_enabled: boolean; mfa_setup_required: boolean }

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
}

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
	created_at: string; updated_at: string;
}

export type JobStatus = 'queued' | 'sent' | 'succeeded' | 'failed' | 'timed_out' | 'error' | 'cancelled' | 'lost' | 'expired';
export interface Job {
	id: string; agent_id: string; hostname: string; script_id: string | null; script_name: string | null; interpreter: Interpreter;
	status: JobStatus; exit_code: number | null; created_by_name: string | null; created_at: string; sent_at: string | null;
	finished_at: string | null; duration_ms: number | null;
}
export interface JobDetail extends Job { body: string; args: string[]; timeout_secs: number; stdout: string; stderr: string }

export interface Dashboard {
	agents_total: number; agents_online: number; clients: number; by_os: Record<string, number>;
	jobs_24h: Record<string, number>; high_disk: AgentSummary[];
}

export interface Session { id: string; created_at: string; last_seen_at: string; expires_at: string; user_agent: string | null; current: boolean }
