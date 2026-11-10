import type {
	ContentStage, DetectionSource, EventKind, ExclusionKind, ProductKind, ProtectionState, QuarantineState, ResponseActionName, RuleMode, SecurityAction,
	SecurityActionRow, SecurityActionStatus, TelemetryEvent, ThreatSeverity, ThreatStatus, Verdict
} from '#lib/types.js';
import type { Tone } from '#lib/ui/Badge.svelte';

export const stateLabels: Record<ProtectionState, string> = {
	threats: 'Active threats',
	unprotected: 'Unprotected',
	at_risk: 'At risk',
	unknown: 'No data',
	protected: 'Protected'
};

export const stateHelp: Record<ProtectionState, string> = {
	threats: 'The antivirus reports a threat it hasn’t dealt with.',
	unprotected: 'No antivirus product is switched on.',
	at_risk: 'Real-time protection is off, or the signatures are more than 3 days old.',
	unknown: 'The agent hasn’t reported its protection yet (older agents never do).',
	protected: 'Antivirus on, scanning in real time, with current signatures.'
};

/** Worst first, the order of the fleet view's tiles and filters. */
export const states: ProtectionState[] = ['threats', 'unprotected', 'at_risk', 'unknown', 'protected'];

export const productLabels: Record<ProductKind, string> = { defender: 'Microsoft Defender', clamav: 'ClamAV', xprotect: 'XProtect', rmm: 'RMM sensor', other: 'Other' };

export const actionLabels: Record<SecurityAction | ResponseActionName, string> = {
	quick_scan: 'Quick scan',
	full_scan: 'Full scan',
	update_signatures: 'Update signatures',
	kill_process: 'Kill process',
	quarantine_file: 'Quarantine file',
	restore_file: 'Restore file',
	delete_quarantined: 'Delete quarantined file',
	isolate: 'Isolate network',
	release: 'Release from isolation',
	collect_triage: 'Collect triage package',
	scan_path: 'Scan a path'
};
/** For sentences: "a quick scan is running". */
export const actionNouns: Record<SecurityAction | ResponseActionName, string> = {
	quick_scan: 'quick scan',
	full_scan: 'full scan',
	update_signatures: 'signature update',
	kill_process: 'process kill',
	quarantine_file: 'quarantine',
	restore_file: 'restore',
	delete_quarantined: 'deletion',
	isolate: 'network isolation',
	release: 'release from isolation',
	collect_triage: 'triage collection',
	scan_path: 'path scan'
};

/** One line saying what a response action did to what: "Kill process 4412 and its children". */
export function actionTitle(a: Pick<SecurityActionRow, 'action' | 'params'>): string {
	const p = a.params ?? {};
	switch (a.action) {
		case 'kill_process':
			return `Kill process ${p.pid ?? ''}${p.tree ? ' and its children' : ''}`;
		case 'quarantine_file':
			return 'Quarantine file';
		case 'scan_path':
			return 'Scan a path';
		case 'isolate':
			return Array.isArray(p.allow) && p.allow.length ? `Isolate network (also allowing ${p.allow.join(', ')})` : 'Isolate network';
		default:
			return actionLabels[a.action] ?? a.action;
	}
}
/** The path or target an action was about, shown in mono under its title. */
export function actionTarget(a: Pick<SecurityActionRow, 'params'>): string | null {
	const p = a.params ?? {};
	return typeof p.path === 'string' ? p.path : null;
}
export const responseActions: ResponseActionName[] = ['kill_process', 'quarantine_file', 'restore_file', 'delete_quarantined', 'isolate', 'release', 'collect_triage', 'scan_path'];

export const actionStatusTone: Record<SecurityActionStatus, Tone> = { sent: 'info', running: 'info', succeeded: 'success', failed: 'danger', lost: 'warning' };
export const actionStatusLabels: Record<SecurityActionStatus, string> = { sent: 'Starting', running: 'Running', succeeded: 'Done', failed: 'Failed', lost: 'Lost' };

export const severityTone: Record<ThreatSeverity, Tone> = { severe: 'danger', high: 'danger', moderate: 'warning', low: 'neutral', unknown: 'neutral' };
export const severityLabels: Record<ThreatSeverity, string> = { severe: 'Severe', high: 'High', moderate: 'Moderate', low: 'Low', unknown: 'Unrated' };

export const threatStatusTone: Record<ThreatStatus, Tone> = { active: 'danger', quarantined: 'neutral', removed: 'neutral', blocked: 'neutral', allowed: 'warning', unknown: 'neutral' };
export const threatStatusLabels: Record<ThreatStatus, string> = {
	active: 'Active',
	quarantined: 'Quarantined',
	removed: 'Removed',
	blocked: 'Blocked',
	allowed: 'Allowed',
	unknown: 'Unknown'
};

/** Defender lists resources as `file:_C:\path`; show the path. */
export function resourceLabel(r: string): string {
	const m = r.match(/^[a-z]+:_(.*)$/i);
	return m ? m[1] : r;
}

export const sourceLabels: Record<DetectionSource, string> = { product: 'Antivirus', file: 'File scan', behaviour: 'Behaviour' };

export const verdictLabels: Record<Verdict, string> = { true_positive: 'True positive', false_positive: 'False positive', benign: 'Benign' };
export const verdictTone: Record<Verdict, Tone> = { true_positive: 'danger', false_positive: 'neutral', benign: 'neutral' };

export const modeLabels: Record<RuleMode, string> = { disabled: 'Disabled', audit: 'Audit', alert: 'Alert', block: 'Block' };
export const modeHelp: Record<RuleMode, string> = {
	disabled: 'Switched off everywhere (the kill switch).',
	audit: 'Recorded quietly: no alert, no action. For trying a rule out.',
	alert: 'Raises a detection and an alert.',
	block: 'Stops it (kills the process or quarantines the file) where the policy allows prevention.'
};

export const stageLabels: Record<ContentStage, string> = { canary: 'Canary', general: 'General', rolled_back: 'Rolled back', retired: 'Retired' };
export const stageTone: Record<ContentStage, Tone> = { canary: 'info', general: 'success', rolled_back: 'danger', retired: 'neutral' };
export const stageHelp: Record<ContentStage, string> = {
	canary: 'Running on canary clients only, soaking before it goes to everyone.',
	general: 'What every agent runs.',
	rolled_back: 'Pulled: agents went back to the previous version.',
	retired: 'Replaced by a newer general version.'
};

export const quarantineStateLabels: Record<QuarantineState, string> = { quarantined: 'Quarantined', restored: 'Restored', deleted: 'Deleted', gone: 'Gone' };

export const exclusionKindLabels: Record<ExclusionKind, string> = { path: 'Path', sha256: 'File hash', rule: 'Rule', process: 'Process' };
export const exclusionKindHints: Record<ExclusionKind, string> = {
	path: 'A file or folder, e.g. C:\\Builds\\ or /srv/backups/. Wildcards: *',
	sha256: 'The file’s SHA-256, 64 hex characters',
	rule: 'A rule id, e.g. RMM-B-0018',
	process: 'An executable name or path whose activity is ignored, e.g. backup.exe'
};

export const eventKindLabels: Record<EventKind, string> = { process: 'Process', network: 'Network', file: 'File', registry: 'Registry', module: 'Module' };
export const eventKinds: EventKind[] = ['process', 'network', 'file', 'registry', 'module'];

/** A one-line description of a telemetry event. */
export function eventSummary(e: TelemetryEvent): string {
	const who = e.process ? `${e.process.name} (${e.process.pid})` : '';
	switch (e.kind) {
		case 'process':
			return e.process?.command_line || e.process?.exe || who;
		case 'network': {
			const n = e.network;
			if (!n) return e.action;
			const remote = n.remote_addr ? ` → ${n.remote_addr}:${n.remote_port}` : '';
			return `${n.protocol.toUpperCase()} ${n.local_addr}:${n.local_port}${remote}`;
		}
		case 'file':
			return e.file ? (e.file.old_path ? `${e.file.old_path} → ${e.file.path}` : e.file.path) : e.action;
		case 'registry':
			return e.registry ? `${e.registry.key}${e.registry.value ? `\\${e.registry.value}` : ''}${e.registry.data ? ` = ${e.registry.data}` : ''}` : e.action;
		case 'module':
			return e.module ? e.module.path ?? e.module.name : e.action;
	}
}

/** `T1059.001` → its page on attack.mitre.org. */
export function mitreUrl(t: string): string {
	const [base, sub] = t.trim().toUpperCase().split('.');
	return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`;
}

/**
 * A detection's context, as the server sends it: the triggering event first, then its
 * process's ancestors (action `running`, nearest first), then related events.
 */
export function splitContext(context: TelemetryEvent[]): { trigger: TelemetryEvent | null; ancestors: TelemetryEvent[]; related: TelemetryEvent[] } {
	const [trigger, ...rest] = context;
	let n = 0;
	while (n < rest.length && rest[n].action === 'running') n++;
	return { trigger: trigger ?? null, ancestors: rest.slice(0, n), related: rest.slice(n) };
}

export const confidenceLabels: Record<'low' | 'medium' | 'high', string> = { low: 'Low', medium: 'Medium', high: 'High' };
