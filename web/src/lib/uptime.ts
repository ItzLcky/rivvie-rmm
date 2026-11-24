/** Uptime monitors and backup jobs (docs/design/uptime.md, docs/design/backups.md). */
import type { Tone } from '#lib/ui/Badge.svelte';

export type MonitorKind = 'ping' | 'tcp' | 'http' | 'tls' | 'dns';
export type MonitorState = 'up' | 'down' | 'unknown';

export const monitorKinds: { value: MonitorKind; label: string; hint: string }[] = [
	{ value: 'http', label: 'Website (HTTP)', hint: 'A URL answers with the right status, and optionally contains a keyword.' },
	{ value: 'ping', label: 'Ping', hint: 'A host answers ICMP echo.' },
	{ value: 'tcp', label: 'TCP port', hint: 'A port accepts connections (a database, mail, RDP).' },
	{ value: 'tls', label: 'TLS certificate', hint: 'A server shakes hands; its certificate is read for its expiry.' },
	{ value: 'dns', label: 'DNS record', hint: 'A name resolves, optionally to an expected answer.' }
];
export const monitorKindLabel = (k: string) => monitorKinds.find((m) => m.value === k)?.label ?? k;

export const monitorTone: Record<MonitorState, Tone> = { up: 'success', down: 'danger', unknown: 'neutral' };
export const monitorLabel: Record<MonitorState, string> = { up: 'Up', down: 'Down', unknown: 'Unknown' };

export interface CertDetails { subject: string; issuer: string; sans: string[]; not_before: string; not_after: string; untrusted: string | null }

export interface Monitor {
	id: string; client_id: string; client_name: string; site_id: string; site_name: string; name: string; kind: MonitorKind; config: Record<string, unknown>;
	target: string; runner: 'agent' | 'server'; agent_id: string | null; runner_agent_id: string | null; runner_hostname: string | null; runner_online: boolean;
	interval_secs: number; timeout_secs: number; enabled: boolean; state: MonitorState; state_since: string; fail_count: number; last_at: string | null;
	last_ms: number | null; last_message: string | null; last_value: number | null; cert_not_after: string | null; cert: CertDetails | null; created_at: string;
	open_alerts: number; uptime_24h: number | null; uptime_30d: number | null;
}
export interface MonitorDay { day: string; checks: number; failures: number; uptime: number | null }
export interface MonitorResult { ts: string; ok: boolean; ms: number | null; message: string }
export interface MonitorAlert { id: string; title: string; severity: 'critical' | 'warning' | 'info'; kind: string; opened_at: string; acknowledged_at: string | null }
export type MonitorDetail = Monitor & { days: MonitorDay[]; alerts: MonitorAlert[]; recent: MonitorResult[] };
export interface UptimePoint { ts: string; checks: number; failures: number; avg_ms: number | null; max_ms: number | null }
export interface UptimeSummary { monitors: number; up: number; down: number; unknown: number; disabled: number; uptime_30d: number | null }

/** "99.95%", or a dash without checks. */
export const uptimePct = (v: number | null | undefined) => (v == null ? '–' : `${v >= 99.995 ? 100 : v}%`);

/** Days left on a certificate (negative once expired). */
export const certDays = (notAfter: string | null) => (notAfter ? Math.floor((Date.parse(notAfter) - Date.now()) / 86_400_000) : null);

export type BackupResult = 'success' | 'warning' | 'failed' | 'running' | 'unknown';
export const backupTone: Record<BackupResult, Tone> = { success: 'success', warning: 'warning', failed: 'danger', running: 'info', unknown: 'neutral' };
export const backupLabel: Record<BackupResult, string> = { success: 'Succeeded', warning: 'Warnings', failed: 'Failed', running: 'Running', unknown: 'Unknown' };
export const providerLabels: Record<string, string> = {
	wsb: 'Windows Server Backup', veeam: 'Veeam', restic: 'restic', borg: 'Borg', timemachine: 'Time Machine', file_age: 'Backup files'
};
export interface BackupJob {
	agent_id: string; hostname: string; online: boolean; client_id: string; client_name: string; site_name: string; provider: string; job: string;
	last_run_at: string | null; last_success_at: string | null; last_result: BackupResult; message: string; size_bytes: number | null; updated_at: string; alerting: boolean;
}
