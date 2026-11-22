/** Software deployment: the catalog, per-device state and runs (docs/design/software.md). */
import type { Tone } from '#lib/ui/Badge.svelte';

export type Want = 'present' | 'latest' | 'absent';
export type SoftwareOp = 'install' | 'upgrade' | 'uninstall';
export type SoftwareRunStatus = 'queued' | 'sent' | 'succeeded' | 'failed' | 'lost' | 'expired' | 'cancelled';

export interface SoftwarePackage {
	id: string;
	client_id: string | null;
	client_name: string | null;
	name: string;
	description: string;
	publisher: string | null;
	winget_id: string | null;
	choco_id: string | null;
	apt_name: string | null;
	dnf_name: string | null;
	version: string | null;
	installer: { name: string; kind: 'msi' | 'exe'; size: number; sha256: string } | null;
	silent_args: string;
	uninstall_cmd: string | null;
	product_code: string | null;
	detect_name: string | null;
	platforms: ('windows' | 'linux')[];
	installed_on: number;
	updates: number;
	policies: number;
	created_at: string;
	updated_at: string;
}

export interface SoftwareDevice {
	agent_id: string;
	hostname: string;
	os_family: string;
	online: boolean;
	client_id: string;
	client_name: string;
	site_name: string;
	package_id: string;
	package_name: string;
	pin: string | null;
	installed: string | null;
	available: string | null;
	ignored: string | null;
	provider: string | null;
	checked_at: string | null;
	desired: Want | null;
	policy_items: string[];
	compliant: boolean | null;
	last_run: { id: string; op: SoftwareOp; status: SoftwareRunStatus; trigger: string; at: string; error: string | null } | null;
	fail_count: number;
	last_error: string | null;
}

export interface SoftwareRun {
	id: string;
	agent_id: string;
	hostname: string;
	client_id: string;
	client_name: string;
	package_id: string | null;
	package_name: string;
	op: SoftwareOp;
	trigger: 'manual' | 'policy';
	policy_item_id: string | null;
	created_by_name: string | null;
	status: SoftwareRunStatus;
	stage: string | null;
	progress: string | null;
	error: string | null;
	provider: string | null;
	from_version: string | null;
	to_version: string | null;
	reboot_required: boolean;
	created_at: string;
	sent_at: string | null;
	finished_at: string | null;
	duration_ms: number | null;
	output?: string;
}

export interface AgentSoftware {
	capable: boolean;
	providers: string[];
	scanned_at: string | null;
	scan_requested_at: string | null;
	scan_error: string | null;
	items: SoftwareDevice[];
	runs: SoftwareRun[];
}

export interface SoftwareUpdates {
	items: SoftwareDevice[];
	packages: { package_id: string; name: string; devices: number }[];
}

export const wantLabels: Record<Want, string> = { present: 'Installed', latest: 'Installed and kept current', absent: 'Not installed' };
export const wantHints: Record<Want, string> = {
	present: 'Install it where it’s missing (and bring an older install up to the pinned version). Never upgrades.',
	latest: 'Install it where it’s missing and upgrade it whenever a newer version is on offer, inside the window.',
	absent: 'Uninstall it wherever it’s found.'
};
export const opLabels: Record<SoftwareOp, string> = { install: 'Install', upgrade: 'Upgrade', uninstall: 'Uninstall' };
export const opProgress: Record<SoftwareOp, string> = { install: 'Installing…', upgrade: 'Upgrading…', uninstall: 'Uninstalling…' };
export const opPast: Record<SoftwareOp, string> = { install: 'Installed', upgrade: 'Upgraded', uninstall: 'Uninstalled' };
export const providerLabels: Record<string, string> = { winget: 'winget', choco: 'Chocolatey', apt: 'apt', dnf: 'dnf', installer: 'Uploaded installer', fake: 'Test provider' };

export const runTone: Record<SoftwareRunStatus, Tone> = { queued: 'neutral', sent: 'info', succeeded: 'success', failed: 'danger', lost: 'warning', expired: 'neutral', cancelled: 'neutral' };
export const runLabel: Record<SoftwareRunStatus, string> = { queued: 'Queued', sent: 'Running', succeeded: 'Succeeded', failed: 'Failed', lost: 'Lost', expired: 'Expired', cancelled: 'Cancelled' };

/** How a device stands against what its policies ask for. */
export function standing(d: SoftwareDevice): { tone: Tone; label: string; title?: string } | null {
	if (d.last_run && (d.last_run.status === 'queued' || d.last_run.status === 'sent')) return { tone: 'info', label: d.last_run.status === 'queued' ? 'Waiting for the device' : opProgress[d.last_run.op] };
	if (d.compliant === true) return { tone: 'success', label: 'Compliant' };
	if (d.compliant === false) {
		if (d.fail_count > 0) return { tone: 'danger', label: 'Failing', title: d.last_error ?? undefined };
		return { tone: 'warning', label: d.desired === 'absent' ? 'Still installed' : d.installed ? 'Out of date' : 'Missing' };
	}
	if (d.desired && !d.checked_at) return { tone: 'neutral', label: 'Not scanned yet' };
	if (d.desired && !d.provider) return { tone: 'neutral', label: 'Can’t check', title: 'Nothing on the device can look this package up' };
	return null;
}

export const sourcesOf = (p: SoftwarePackage): string[] =>
	[p.winget_id && 'winget', p.choco_id && 'Chocolatey', p.apt_name && 'apt', p.dnf_name && 'dnf', p.installer && p.installer.kind.toUpperCase()].filter(Boolean) as string[];
