/** Network discovery and SNMP monitoring (docs/design/network.md). */
import type { Tone } from '#lib/ui/Badge.svelte';

export type DeviceKind = 'switch' | 'router' | 'firewall' | 'printer' | 'ap' | 'ups' | 'nas' | 'server' | 'windows' | 'linux' | 'other';
export const kindOptions: { value: DeviceKind; label: string }[] = [
	{ value: 'switch', label: 'Switch' },
	{ value: 'router', label: 'Router' },
	{ value: 'firewall', label: 'Firewall' },
	{ value: 'printer', label: 'Printer' },
	{ value: 'ap', label: 'Access point' },
	{ value: 'ups', label: 'UPS' },
	{ value: 'nas', label: 'NAS' },
	{ value: 'server', label: 'Server' },
	{ value: 'windows', label: 'Windows computer' },
	{ value: 'linux', label: 'Linux computer' },
	{ value: 'other', label: 'Other' }
];
export const kindLabel = (k: string) => kindOptions.find((o) => o.value === k)?.label ?? k;

export interface NetSummary { unmanaged: number; devices: number; down: number }

export interface Candidate { id: string; hostname: string; online: boolean; capable: boolean }
export interface ScanRow {
	id: string; status: string; subnets: string[]; scanned: number; found: number; new_hosts: number; error: string | null;
	requested_by_name: string | null; created_at: string; finished_at: string | null;
}
export interface SiteNetwork {
	site_id: string; site_name: string; client_id: string; agent_id: string | null; agent_hostname: string | null; agent_online: boolean; agent_capable: boolean;
	subnets: string[]; discovery_hours: number; credential_ids: string[]; poll_secs: number; candidates: Candidate[]; last_scan: ScanRow | null; devices: number;
}

export type DiscoveredState = 'unmanaged' | 'managed' | 'monitored' | 'ignored' | 'known';
export interface Discovered {
	id: string; site_id: string; site_name: string; client_id: string; client_name: string; ip: string; mac: string | null; hostname: string | null; mdns_name: string | null;
	vendor: string | null; sys_name: string | null; sys_descr: string | null; sys_object_id: string | null; sys_location: string | null; credential_id: string | null;
	open_ports: number[]; methods: string[]; kind: DeviceKind; status: string; note: string; agent_id: string | null; agent_hostname: string | null;
	net_device_id: string | null; online: boolean; rtt_ms: number | null; first_seen_at: string; last_seen_at: string; state: DiscoveredState; name: string;
}

/** class 3 consumed (toner, ink), 4 filled (waste); kind 3 toner, 4 waste toner, 5 ink, 9 drum, 12 fuser. */
export interface Supply { index: number; description: string; class: number; kind: number; percent: number | null }
export interface Storage { descr: string; kind: 'ram' | 'disk'; used: number; total: number }
export interface NetDevice {
	id: string; site_id: string; site_name: string; client_id: string; client_name: string; name: string; host: string; port: number; credential_id: string; credential_name: string;
	kind: DeviceKind; enabled: boolean; poll_secs: number | null; sys_descr: string | null; sys_name: string | null; sys_object_id: string | null; sys_location: string | null;
	vendor: string | null; mac: string | null; state: 'up' | 'down' | 'unknown'; state_since: string; last_poll_at: string | null; last_ok_at: string | null; last_error: string | null;
	rtt_ms: number | null; uptime_secs: number | null; cpu_percent: number | null; mem_used: number | null; mem_total: number | null; storage: Storage[]; supplies: Supply[];
	created_at: string; agent_id: string | null; agent_hostname: string | null; agent_online: boolean; open_alerts: number; interfaces: number; interfaces_up: number;
}
export interface NetInterface {
	if_index: number; name: string; descr: string; alias: string; if_type: number; speed_bps: number; admin_status: number; oper_status: number; status_since: string;
	monitored: boolean; in_bps: number | null; out_bps: number | null; util_pct: number | null; in_errors: number; out_errors: number; in_discards: number; out_discards: number; last_at: string | null;
}
export interface NetAlert { id: string; title: string; severity: 'critical' | 'warning' | 'info'; kind: string; opened_at: string; acknowledged_at: string | null }

export type DeviceDetail = Omit<NetDevice, 'interfaces'> & { interfaces: NetInterface[]; alerts: NetAlert[] };
export interface DevicePoint { ts: string; reachable_pct: number; rtt_ms: number | null; cpu_percent: number | null; mem_used: number | null; mem_total: number | null }
export interface InterfacePoint { ts: string; in_bps: number | null; out_bps: number | null; util_pct: number | null; up_pct: number }

export interface Credential {
	id: string; client_id: string; name: string; version: 'v2c' | 'v3'; username: string; auth_proto: string | null; priv_proto: string | null; context: string;
	devices: number; created_at: string; updated_at: string;
}

export const stateTone: Record<string, Tone> = { up: 'success', down: 'danger', unknown: 'neutral' };
export const stateLabel: Record<string, string> = { up: 'Up', down: 'Down', unknown: 'Not read yet' };
export const discoveredTone: Record<string, Tone> = { unmanaged: 'warning', managed: 'success', monitored: 'info', ignored: 'neutral', known: 'neutral' };
export const discoveredLabel: Record<string, string> = { unmanaged: 'Unmanaged', managed: 'Managed', monitored: 'Monitored', ignored: 'Ignored', known: 'Known' };

/** ifOperStatus / ifAdminStatus (RFC 2863). */
export const ifStatus = (n: number) => ({ 1: 'up', 2: 'down', 3: 'testing', 5: 'dormant', 6: 'not present', 7: 'lower layer down' })[n] ?? 'unknown';

/** Bits per second as 12.3 Mbit/s. */
export function bps(n: number | null | undefined): string {
	if (n == null) return '–';
	const u = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'];
	let v = n;
	let i = 0;
	while (v >= 1000 && i < u.length - 1) (v /= 1000), i++;
	return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

export const portNames: Record<number, string> = {
	21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 135: 'RPC', 139: 'NetBIOS', 161: 'SNMP', 443: 'HTTPS', 445: 'SMB', 515: 'LPD', 631: 'IPP',
	3389: 'RDP', 5985: 'WinRM', 8080: 'HTTP', 8443: 'HTTPS', 9100: 'JetDirect'
};
export const portLabel = (p: number) => (portNames[p] ? `${p} ${portNames[p]}` : String(p));
