/**
 * Policy sets: fixed ids, labels, the tree, and the field paths that per-field overrides work
 * with (docs/design/policies.md). Overrides are sparse: only the fields that differ, merged into
 * the inherited config key by key (objects merge, everything else replaces).
 */
import type { ChainEntry, Config, ItemView, Module, Reason, SetRow } from './types';

export const ROOT_SET = '00000000-0000-4000-8001-000000000000';
export const PATCH_ITEM = '00000000-0000-4000-8000-000000000001';
export const SECURITY_ITEM = '00000000-0000-4000-8000-000000000002';
export const REMOTE_ITEM = '00000000-0000-4000-8000-000000000003';
export const AGENT_ITEM = '00000000-0000-4000-8000-000000000004';
export const TRAY_ITEM = '00000000-0000-4000-8000-000000000007';

export const moduleLabels: Record<Module, string> = {
	alert: 'Alerts',
	schedule: 'Scheduled scripts',
	patch: 'Patching',
	security: 'Security',
	remote_access: 'Remote access',
	agent: 'Agent',
	software: 'Software',
	automation: 'Automations',
	tray: 'Tray app'
};
/** Singular, for one item: "the Patching policy". */
export const moduleNoun: Record<Module, string> = {
	alert: 'alert policy',
	schedule: 'scheduled script',
	patch: 'patch policy',
	security: 'security policy',
	remote_access: 'remote access policy',
	agent: 'agent policy',
	software: 'software requirement',
	automation: 'automation',
	tray: 'tray app policy'
};

/** Sections of the policy set page, in order; `?section=`. */
export const sections = [
	{ value: 'alerts', module: 'alert' },
	{ value: 'schedules', module: 'schedule' },
	{ value: 'software', module: 'software' },
	{ value: 'automations', module: 'automation' },
	{ value: 'patching', module: 'patch' },
	{ value: 'security', module: 'security' },
	{ value: 'remote', module: 'remote_access' },
	{ value: 'agent', module: 'agent' },
	{ value: 'tray', module: 'tray' }
] as const satisfies { value: string; module: Module }[];
export const sectionOf: Record<Module, string> = Object.fromEntries(sections.map((s) => [s.module, s.value])) as Record<Module, string>;
export const singleModules: Module[] = ['patch', 'security', 'remote_access', 'agent', 'tray'];

/** Where one item is edited, as it applies in `setId`. */
export function itemHref(setId: string, item: Pick<ItemView, 'id' | 'module'>): string {
	const one = singleModules.includes(item.module);
	return `/policies/sets/${setId}?section=${sectionOf[item.module]}${one ? '' : `&item=${item.id}`}`;
}
export function setHref(id: string, section?: string): string {
	return `/policies/sets/${id}${section ? `?section=${section}` : ''}`;
}

export const reasonLabels: Record<Reason, string> = {
	pin: 'Pinned to this device',
	site: 'Assigned to its site',
	client: 'Assigned to its client',
	default: 'Default of its category'
};

/** The sets in tree order (parents before children, siblings as the server sorted them). */
export function treeOrder(rows: SetRow[]): SetRow[] {
	const kids = new Map<string | null, SetRow[]>();
	const ids = new Set(rows.map((r) => r.id));
	for (const r of rows) {
		// A set whose parent isn't visible (another client's) hangs off nothing: show it at the top.
		const p = r.parent_id && ids.has(r.parent_id) ? r.parent_id : null;
		kids.set(p, [...(kids.get(p) ?? []), r]);
	}
	const out: SetRow[] = [];
	const walk = (p: string | null) => {
		for (const r of kids.get(p) ?? []) {
			out.push(r);
			walk(r.id);
		}
	};
	walk(null);
	return out;
}

/** "Acme Corp only" / "MSP-wide". */
export function ownerLabel(s: { client_id: string | null; client_name?: string | null }): string {
	return s.client_id ? `${s.client_name ?? 'One client'} only` : 'MSP-wide';
}

// --- Field paths -------------------------------------------------------------------------------

/** Values replaced whole rather than merged: a patch window is one setting. */
const ATOMIC = new Set(['window']);

const isObj = (v: unknown): v is Config => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The leaf fields of a config by dotted path, the unit a per-field override works on. */
export function leaves(c: Config, prefix = ''): Map<string, unknown> {
	const out = new Map<string, unknown>();
	for (const [k, v] of Object.entries(c)) {
		const p = prefix ? `${prefix}.${k}` : k;
		if (isObj(v) && !ATOMIC.has(p) && Object.keys(v).length) for (const [q, x] of leaves(v, p)) out.set(q, x);
		else out.set(p, v);
	}
	return out;
}

export function getPath(c: Config | null | undefined, path: string): unknown {
	let v: unknown = c;
	for (const k of path.split('.')) v = isObj(v) ? v[k] : undefined;
	return v;
}

/** Copy of `c` with `path` set (intermediate objects created). */
export function setPath(c: Config, path: string, value: unknown): Config {
	const [k, ...rest] = path.split('.');
	if (!rest.length) return { ...c, [k]: value };
	return { ...c, [k]: setPath(isObj(c[k]) ? (c[k] as Config) : {}, rest.join('.'), value) };
}

/** Copy of `c` without `path` (and without objects that become empty). */
export function unsetPath(c: Config, path: string): Config {
	const [k, ...rest] = path.split('.');
	const out = { ...c };
	if (!rest.length || !isObj(c[k])) {
		delete out[k];
		return out;
	}
	const inner = unsetPath(c[k] as Config, rest.join('.'));
	if (Object.keys(inner).length) out[k] = inner;
	else delete out[k];
	return out;
}

/** True when `path` names this field or a field inside it, or the other way round. */
export const overlaps = (a: string, b: string) => a === b || a.startsWith(`${b}.`) || b.startsWith(`${a}.`);

/** The override holds this field (or part of it). */
export function inOverride(o: Config | null | undefined, path: string): boolean {
	return !!o && [...leaves(o).keys()].some((k) => overlaps(k, path));
}

/** Leaf fields whose value in `edited` differs from `base`. */
export function changedFields(base: Config, edited: Config): Map<string, unknown> {
	const out = new Map<string, unknown>();
	for (const [p, v] of leaves(edited)) if (JSON.stringify(getPath(base, p) ?? null) !== JSON.stringify(v ?? null)) out.set(p, v);
	return out;
}

/** The set a field's value comes from (`sources` is keyed by leaf; a field may be an object). */
export function sourceOf(sources: Record<string, string>, path: string): string | undefined {
	if (sources[path]) return sources[path];
	const k = Object.keys(sources).find((s) => overlaps(s, path));
	return k ? sources[k] : undefined;
}

export function chainName(chain: ChainEntry[], id: string | undefined): string {
	return chain.find((c) => c.id === id)?.name ?? 'a set above';
}

/** Readable names of the fields an override changes, for summaries ("Severity, Threshold"). */
export const fieldLabels: Record<string, string> = {
	enabled: 'On/off',
	severity: 'Severity',
	channel_ids: 'Channels',
	notify_resolved: 'Clear notice',
	renotify_minutes: 'Reminders',
	ticket_board_id: 'Ticket board',
	ticket_priority: 'Ticket priority',
	ticket_auto_resolve: 'Ticket auto-resolve',
	run_script_id: 'Script on open',
	'params.minutes': 'Duration',
	'params.threshold': 'Threshold',
	'params.services': 'Services',
	'params.auto_only': 'Automatic services',
	'params.exclude': 'Excepted services',
	'params.script_id': 'Script',
	'params.min_level': 'Level',
	'params.pattern': 'Pattern',
	'params.sources': 'Sources',
	'params.channels': 'Windows logs',
	'params.event_ids': 'Event IDs',
	'params.threats': 'Threats',
	'params.reboot_hours': 'Pending restart',
	'params.failed': 'Failed installs',
	args: 'Arguments',
	state: 'Requirement',
	bootstrap_choco: 'Chocolatey install',
	package_id: 'Package',
	timeout_secs: 'Timeout',
	auto_approve_severities: 'Severities',
	auto_approve_categories: 'Categories',
	deferral_days: 'Deferral',
	auto_install: 'Automatic install',
	reboot_policy: 'Restart',
	window: 'Install window',
	wake_before_minutes: 'Wake before window',
	sensor_enabled: 'Sensor',
	quick_scan_hours: 'Quick scans',
	full_scan_days: 'Full scans',
	auto_quarantine: 'Quarantine',
	prevention: 'Prevention',
	canaries: 'Decoy files',
	telemetry_mb: 'Telemetry store',
	realtime: 'Real-time',
	scan_on_write: 'Scan on write',
	archive_depth: 'Archive depth',
	database_max_age_hours: 'Database age',
	desktop_enabled: 'Remote desktop',
	desktop_consent: 'Ask first',
	shell_enabled: 'Terminal',
	files_enabled: 'Files',
	auto_update: 'Automatic updates'
};
export function fieldLabel(path: string): string {
	return fieldLabels[path] ?? path.replace(/^params\./, '').replaceAll('_', ' ');
}
/** The fields an override holds, named: "Severity, Threshold". */
export function overriddenFields(o: { enabled: boolean | null; config: Config } | null): string[] {
	if (!o) return [];
	const names = [...new Set([...leaves(o.config).keys()].map((p) => fieldLabel(p.startsWith('window') ? 'window' : p)))];
	return o.enabled != null ? [fieldLabel('enabled'), ...names] : names;
}

/** Sets below the origin that changed fields of this item, as it reaches `chain`'s last set. */
export function overriddenAlong(v: Pick<ItemView, 'sources' | 'origin_set_id'>, chain: ChainEntry[]): { set: ChainEntry; fields: string[] }[] {
	const by = new Map<string, string[]>();
	for (const [p, s] of Object.entries(v.sources)) if (s !== v.origin_set_id) by.set(s, [...(by.get(s) ?? []), fieldLabel(p.startsWith('window.') ? 'window' : p)]);
	return chain.filter((c) => by.has(c.id)).map((c) => ({ set: c, fields: [...new Set(by.get(c.id))] }));
}

// --- Automations (docs/design/automations.md) ----------------------------------------------------

export type AutomationTrigger = 'enrollment' | 'agent_online' | 'alert_opened' | 'patch_reboot_pending' | 'tag_added' | 'field_changed' | 'run_once';
export const triggerLabels: Record<AutomationTrigger, string> = {
	enrollment: 'Device enrolls',
	agent_online: 'Device comes back online',
	alert_opened: 'Alert opens',
	patch_reboot_pending: 'Patch install leaves a restart pending',
	tag_added: 'Tag added to a device',
	field_changed: 'Custom field changes',
	run_once: 'Once per device'
};
export const triggerHelp: Record<AutomationTrigger, string> = {
	enrollment: 'Runs the first time a new device connects, once.',
	agent_online: 'Runs when a device connects again after being offline for at least the time you set.',
	alert_opened: 'Runs when an alert of the chosen type opens on a device (not while it is muted).',
	patch_reboot_pending: 'Runs when a patch install has finished and the device still needs a restart.',
	tag_added: 'Runs when the chosen tag is put on a device that didn’t have it.',
	field_changed: 'Runs when the chosen custom field of a device is set, changed or cleared, by a person, the API or a script. A script that sets the field it watches doesn’t start itself again.',
	run_once: 'Runs once on every device using this set, including devices that join later. Each device has its own status; failed ones can retry, and a reset runs it again.'
};
/** Triggers that happen once per device ever (a row per device holds the state). */
export const oncePerDevice: AutomationTrigger[] = ['enrollment', 'run_once'];

export type RunStatus = 'waiting' | 'pending' | 'succeeded' | 'failed' | 'skipped';
export const runStatusLabels: Record<RunStatus, string> = { waiting: 'Waiting', pending: 'Running', succeeded: 'Succeeded', failed: 'Failed', skipped: 'Skipped' };
export const runReasonLabels: Record<string, string> = {
	maintenance_window: 'waiting for the maintenance window',
	rate_limited: 'over the hourly limit',
	cooldown: 'ran recently on this device',
	own_write: 'set by this automation’s own script',
	expired: 'waited too long',
	no_longer_applies: 'the automation no longer applies',
	script_missing: 'the script was deleted',
	script_other_client: 'the script belongs to another client',
	script_unavailable: 'the script can’t run here',
	timed_out: 'timed out',
	lost: 'the agent lost the job',
	error: 'the script couldn’t start',
	cancelled: 'cancelled',
	failed: 'the script failed',
	expired_job: 'the job expired'
};
export const runReason = (r: string | null) => (r ? (runReasonLabels[r] ?? r.replaceAll('_', ' ')) : '');

Object.assign(fieldLabels, {
	trigger: 'Trigger',
	script_id: 'Script',
	offline_minutes: 'Offline for',
	alert_kind: 'Alert type',
	tag_id: 'Tag',
	field_id: 'Custom field',
	field_value: 'Field value',
	retry_failed: 'Retry failures',
	max_attempts: 'Attempts',
	retry_minutes: 'Retry after',
	cooldown_minutes: 'Cooldown',
	max_runs_per_hour: 'Runs per hour',
	respect_window: 'Maintenance window',
	retain_days: 'Keep runs'
});

/** One line for the list: what starts it. `names` says what the tag and field ids are called. */
export function describeAutomation(c: Config, names?: { tag?: string; field?: string }): string {
	const t = c.trigger as AutomationTrigger;
	switch (t) {
		case 'tag_added':
			return `${triggerLabels[t]}: ${names?.tag ?? 'unknown tag'}`;
		case 'field_changed':
			return `${triggerLabels[t]}: ${names?.field ?? 'unknown field'}${c.field_value != null ? ` → ${c.field_value}` : ''}`;
		case 'agent_online':
			return `${triggerLabels[t]} after ${c.offline_minutes} min offline`;
		case 'alert_opened':
			return `${triggerLabels[t]}: ${String(c.alert_kind ?? '').replaceAll('_', ' ')}`;
		default:
			return triggerLabels[t] ?? String(t ?? '');
	}
}
