import type { Tone } from '#lib/ui/Badge.svelte';
import type { Approval, MaintenanceWindow, PatchCategory, PatchState, RebootPolicy, RunStatus, Severity } from './types';

export const severities: { value: Severity; label: string; tone: Tone }[] = [
	{ value: 'critical', label: 'Critical', tone: 'danger' },
	{ value: 'important', label: 'Important', tone: 'warning' },
	{ value: 'moderate', label: 'Moderate', tone: 'info' },
	{ value: 'low', label: 'Low', tone: 'neutral' },
	{ value: 'unspecified', label: 'Unrated', tone: 'neutral' }
];

export const categories: { value: PatchCategory; label: string; hint: string }[] = [
	{ value: 'security', label: 'Security', hint: 'Security fixes: Windows security updates, apt security pockets, RHSA/Fedora security advisories' },
	{ value: 'critical', label: 'Critical', hint: 'Windows "Critical Updates": non-security fixes for critical bugs' },
	{ value: 'definition', label: 'Definitions', hint: 'Defender and other definition updates' },
	{ value: 'rollup', label: 'Rollups', hint: 'Cumulative updates and update rollups; macOS updates' },
	{ value: 'update', label: 'Updates', hint: 'Ordinary updates and bug fixes, including every Linux package without an advisory' },
	{ value: 'driver', label: 'Drivers', hint: 'Driver updates from Windows Update' },
	{ value: 'feature', label: 'Feature updates', hint: 'Windows feature updates, service packs and upgrades' },
	{ value: 'other', label: 'Other', hint: 'Tools and anything unclassified' }
];

export function severityLabel(s: Severity | null): string {
	return severities.find((x) => x.value === (s ?? 'unspecified'))?.label ?? s ?? 'Unrated';
}
export function severityTone(s: Severity | null): Tone {
	return severities.find((x) => x.value === (s ?? 'unspecified'))?.tone ?? 'neutral';
}
export function categoryLabel(c: PatchCategory): string {
	return categories.find((x) => x.value === c)?.label ?? c;
}

export const stateInfo: Record<PatchState, [Tone, string]> = {
	missing: ['warning', 'Missing'],
	installing: ['info', 'Installing'],
	installed: ['success', 'Installed'],
	failed: ['danger', 'Failed']
};
export const approvalInfo: Record<Approval, [Tone, string]> = {
	pending: ['neutral', 'Not approved'],
	approved: ['success', 'Approved'],
	declined: ['neutral', 'Declined']
};
export const runInfo: Record<RunStatus, [Tone, string]> = {
	queued: ['neutral', 'Queued'],
	sent: ['info', 'Installing'],
	succeeded: ['success', 'Succeeded'],
	partial: ['warning', 'Partly failed'],
	failed: ['danger', 'Failed'],
	lost: ['warning', 'Lost'],
	expired: ['neutral', 'Expired'],
	cancelled: ['neutral', 'Cancelled']
};

export const rebootPolicies: { value: RebootPolicy; label: string; hint: string }[] = [
	{ value: 'never', label: 'Never reboot', hint: 'Install, and report that a restart is pending' },
	{ value: 'if_required', label: 'Reboot if required', hint: 'Restart (with a one-minute warning) when an update needs it' },
	{ value: 'always', label: 'Always reboot', hint: 'Restart after every install that changed something' }
];
export function rebootLabel(r: RebootPolicy): string {
	return rebootPolicies.find((x) => x.value === r)?.label ?? r;
}

export const providerLabels: Record<string, string> = {
	wua: 'Windows Update', pswindowsupdate: 'PSWindowsUpdate', apt: 'apt', dnf: 'dnf', yum: 'yum', pacman: 'pacman',
	softwareupdate: 'softwareupdate', fake: 'test provider', none: 'none'
};

export const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

/** "Sat, Sun 02:00–05:00 Europe/London", or "Any time". */
export function windowLabel(w: Pick<MaintenanceWindow, 'days' | 'start' | 'minutes' | 'tz'>): string {
	if (!w.days?.length || !w.start || !w.minutes) return 'Any time';
	const days = w.days.length === 7 ? 'Every day' : w.days.length === 5 && [1, 2, 3, 4, 5].every((d) => w.days!.includes(d)) ? 'Weekdays' : w.days.map((d) => dayNames[d]).join(', ');
	const [h, m] = w.start.split(':').map(Number);
	const end = (h * 60 + m + w.minutes) % 1440;
	const pad = (n: number) => String(n).padStart(2, '0');
	return `${days} ${w.start}–${pad(Math.floor(end / 60))}:${pad(end % 60)} ${w.tz}`;
}

/** Percentage, rounded down so 99.6% doesn't read as fully patched. */
export function compliancePct(compliant: number, scanned: number): number | null {
	return scanned ? Math.floor((100 * compliant) / scanned) : null;
}
