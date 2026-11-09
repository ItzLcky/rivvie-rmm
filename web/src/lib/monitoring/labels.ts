import type { LogLevel, Policy, PolicyKind, ServiceState, Severity } from '#lib/types.js';
import type { Tone } from '#lib/ui/Badge.svelte';

export const kindLabels: Record<PolicyKind, string> = {
	offline: 'Agent offline',
	cpu: 'CPU',
	memory: 'Memory',
	disk: 'Disk space',
	service: 'Service stopped',
	job_failed: 'Failed job',
	log: 'Event log match'
};

export const kindHelp: Record<PolicyKind, string> = {
	offline: 'The agent hasn’t checked in for a while.',
	cpu: 'CPU use stays at or above a threshold.',
	memory: 'Memory use stays at or above a threshold.',
	disk: 'The fullest volume stays at or above a threshold.',
	service: 'A watched service (systemd unit or Windows service) is stopped or failed.',
	job_failed: 'A script fails, errors or times out. Clears when the same script next succeeds.',
	log: 'An entry in the journal (Linux) or the Event Log (Windows) matches your rules.'
};

export const severityTone: Record<Severity, Tone> = { critical: 'danger', warning: 'warning', info: 'info' };
export const severityLabels: Record<Severity, string> = { critical: 'Critical', warning: 'Warning', info: 'Info' };

export const levelTone: Record<LogLevel, Tone> = { critical: 'danger', error: 'danger', warning: 'warning', info: 'neutral' };

export const serviceTone: Record<ServiceState, Tone> = {
	running: 'success',
	stopped: 'neutral',
	failed: 'danger',
	starting: 'info',
	stopping: 'info',
	paused: 'warning',
	unknown: 'neutral'
};

/** One line saying what a policy checks, e.g. "CPU ≥ 90% for 15 min". */
export function describePolicy(p: Pick<Policy, 'kind' | 'params'>): string {
	const q = p.params as Record<string, unknown>;
	const list = (v: unknown) => (Array.isArray(v) ? (v as string[]) : []);
	switch (p.kind) {
		case 'offline':
			return `Offline for ${q.minutes} min`;
		case 'cpu':
		case 'memory':
		case 'disk':
			return `${kindLabels[p.kind]} ≥ ${q.threshold}% for ${q.minutes} min`;
		case 'service': {
			const names = list(q.services);
			const parts = [q.auto_only ? 'Every automatic service' : '', names.length ? names.slice(0, 3).join(', ') + (names.length > 3 ? ` +${names.length - 3}` : '') : '']
				.filter(Boolean)
				.join(' and ');
			const ex = list(q.exclude).length;
			return `${parts}${ex ? `, ${ex} excluded` : ''}`;
		}
		case 'job_failed':
			return q.script_id ? 'One script fails' : 'Any script fails';
		case 'log': {
			const bits = [`${String(q.min_level ?? 'error')} or worse`];
			if (list(q.sources).length) bits.push(`from ${list(q.sources).join(', ')}`);
			if (Array.isArray(q.event_ids) && q.event_ids.length) bits.push(`IDs ${(q.event_ids as number[]).join(', ')}`);
			if (q.pattern) bits.push(`matching /${q.pattern}/`);
			return bits.join(', ');
		}
	}
}

const dows = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const pad = (n: string) => n.padStart(2, '0');

/** A readable cron expression for the common shapes; the expression itself otherwise. */
export function describeCron(expr: string): string {
	const e = expr.trim();
	const nick: Record<string, string> = { '@hourly': 'Every hour', '@daily': 'Every day at 00:00', '@midnight': 'Every day at 00:00', '@weekly': 'Every Sunday at 00:00', '@monthly': 'On the 1st of every month at 00:00', '@yearly': 'Every 1 January at 00:00', '@annually': 'Every 1 January at 00:00' };
	if (nick[e]) return nick[e];
	const f = e.split(/\s+/);
	if (f.length !== 5) return e;
	const [m, h, dom, mon, dow] = f;
	const num = (s: string) => /^\d+$/.test(s);
	if (m === '*' && h === '*' && dom === '*' && mon === '*' && dow === '*') return 'Every minute';
	const every = /^\*\/(\d+)$/;
	if (every.test(m) && h === '*' && dom === '*' && mon === '*' && dow === '*') return `Every ${m.match(every)![1]} minutes`;
	if (num(m) && h === '*' && dom === '*' && mon === '*' && dow === '*') return `Every hour at :${pad(m)}`;
	if (num(m) && every.test(h) && dom === '*' && mon === '*' && dow === '*') return `Every ${h.match(every)![1]} hours at :${pad(m)}`;
	if (!num(m) || !num(h)) return e;
	const at = `${pad(h)}:${pad(m)}`;
	if (dom === '*' && mon === '*' && dow === '*') return `Every day at ${at}`;
	if (dom === '*' && mon === '*' && dow === '1-5') return `Weekdays at ${at}`;
	if (dom === '*' && mon === '*' && /^\d(,\d)*$/.test(dow)) return `Every ${dow.split(',').map((d) => dows[Number(d) % 7]).join(', ')} at ${at}`;
	if (num(dom) && mon === '*' && dow === '*') return `Monthly on day ${dom} at ${at}`;
	return e;
}
