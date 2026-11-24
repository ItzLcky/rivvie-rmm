import type { LogLevel, PolicyKind, ServiceState, Severity } from '#lib/types.js';
import type { Tone } from '#lib/ui/Badge.svelte';

export const kindLabels: Record<PolicyKind, string> = {
	offline: 'Agent offline',
	cpu: 'CPU',
	memory: 'Memory',
	disk: 'Disk space',
	service: 'Service stopped',
	job_failed: 'Failed job',
	log: 'Event log match',
	security: 'Antivirus',
	patch: 'Patches',
	net_down: 'Network device down',
	net_interface: 'Network interface down',
	net_threshold: 'Network device threshold',
	uptime: 'Uptime monitor',
	backup: 'Backups',
	disk_encryption: 'Disk encryption',
	local_admin: 'Local admin password',
	vulnerability: 'Vulnerabilities'
};

export const kindHelp: Record<PolicyKind, string> = {
	offline: 'The agent hasn’t checked in for a while.',
	cpu: 'CPU use stays at or above a threshold.',
	memory: 'Memory use stays at or above a threshold.',
	disk: 'The fullest volume stays at or above a threshold.',
	service: 'A watched service (systemd unit or Windows service) is stopped or failed.',
	job_failed: 'A script fails, errors or times out. Clears when the same script next succeeds.',
	log: 'An entry in the journal (Linux) or the Event Log (Windows) matches your rules.',
	security: 'Protection is off or out of date, stopped reporting, or the antivirus finds a threat.',
	patch: 'An update fails to install, or a restart to finish updates stays pending.',
	net_down: 'A switch, firewall, printer or other device read over SNMP stops answering.',
	net_interface: 'A monitored port that is switched on has no link.',
	net_threshold: 'A device’s CPU, memory, port traffic or toner level crosses a limit.',
	uptime: 'A website, port, host or DNS name stops answering, answers slowly, or its certificate nears expiry.',
	backup: 'A backup job fails, or hasn’t succeeded for too long.',
	disk_encryption: 'A volume isn’t encrypted, protection stays suspended, or a BitLocker recovery key isn’t escrowed.',
	local_admin: 'Rotating the managed local admin password fails, conflicts with Windows LAPS, or is overdue.',
	vulnerability: 'Installed software has known vulnerabilities: one alert per device, worst CVEs first.'
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
export function describePolicy(p: { kind: PolicyKind; params: Record<string, unknown> }): string {
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
		case 'security': {
			const bits: string[] = [];
			if (q.unprotected) bits.push('no antivirus');
			if (q.realtime_off) bits.push('real-time off');
			if (q.sensor_down) bits.push('sensor not running');
			if (q.sensor_realtime) bits.push('our real-time protection off');
			if (q.database_stale) bits.push('signature database out of date');
			if (q.signature_max_age_hours) bits.push(`signatures over ${q.signature_max_age_hours} h`);
			if (q.stale_hours) bits.push(`no report for ${q.stale_hours} h`);
			if (q.threats === 'any') bits.push('every detection');
			else if (q.threats !== 'off') bits.push('active threats');
			return bits.join(', ') || 'Nothing';
		}
		case 'patch': {
			const bits: string[] = [];
			if (q.failed !== false) bits.push('failed installs');
			if (q.reboot_hours) bits.push(`restart pending over ${q.reboot_hours} h`);
			return bits.join(', ') || 'Nothing';
		}
		case 'net_down':
			return `No answer for ${q.minutes} min${list(q.kinds).length ? ` (${list(q.kinds).join(', ')})` : ''}`;
		case 'net_interface':
			return `Port down for ${q.minutes} min${list(q.names).length ? `: ${list(q.names).join(', ')}` : ''}`;
		case 'net_threshold': {
			const m = q.metric as string;
			if (m === 'supply') return `Toner or ink at or below ${q.threshold}%`;
			return `${m === 'interface_util' ? 'Port use' : kindLabels[m as 'cpu' | 'memory']} ≥ ${q.threshold}% for ${q.minutes} min`;
		}
		case 'uptime': {
			const bits = [`down after ${q.failures ?? 2} failed checks`];
			if (Number(q.cert_days ?? 14) > 0) bits.push(`certificate within ${q.cert_days ?? 14} days`);
			if (q.latency_ms) bits.push(`slower than ${q.latency_ms} ms`);
			const k = list(q.kinds);
			return bits.join(', ') + (k.length ? ` (${k.join(', ')})` : '');
		}
		case 'disk_encryption': {
			const bits = [q.volumes === 'all_fixed' ? 'Every fixed volume' : 'The system volume', 'encrypted'];
			if (q.require_escrow !== false) bits.push('recovery key escrowed');
			return `${bits.join(', ')}; suspended over ${q.grace_hours ?? 24} h`;
		}
		case 'local_admin':
			return `Rotation failed or over ${q.overdue_days ?? 7} days overdue`;
		case 'backup': {
			const p = list(q.providers).map((x) => (x === 'auto' ? 'detected products' : x));
			const s = Array.isArray(q.sources) ? q.sources.length : 0;
			const what = [...p, s ? `${s} source${s === 1 ? '' : 's'}` : ''].filter(Boolean).join(', ');
			return `Failed, or no success for ${q.max_age_hours ?? 26} h${what ? ` (${what})` : ''}${q.require ? '; one must exist' : ''}`;
		}
		case 'vulnerability': {
			const bits = [`${String(q.min_severity ?? 'critical')} or worse`];
			if (q.kev_only) bits.push('known exploited');
			if (q.fix_available_only !== false) bits.push('with a fix');
			if (Number(q.older_than_days ?? 14) > 0) bits.push(`open over ${q.older_than_days ?? 14} days`);
			if (q.min_epss != null) bits.push(`EPSS ≥ ${Math.round(Number(q.min_epss) * 100)}%`);
			return bits.join(', ');
		}
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

const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

/** "Sat, Sun 22:00 for 6 h (Europe/London)" or "until 14 Nov, 18:00". */
export function describeMute(m: { ends_at: string | null; starts_at: string | null; days: number[] | null; start_time: string | null; minutes: number | null; tz: string }, fmt: (iso: string) => string): string {
	if (m.ends_at) return m.starts_at && Date.parse(m.starts_at) > Date.now() ? `${fmt(m.starts_at)} to ${fmt(m.ends_at)}` : `Until ${fmt(m.ends_at)}`;
	const days = (m.days ?? []).map((d) => dayNames[d]).join(', ');
	const mins = m.minutes ?? 0;
	const len = mins % 60 === 0 ? `${mins / 60} h` : `${mins} min`;
	return `${days} ${(m.start_time ?? '').slice(0, 5)} for ${len} (${m.tz})`;
}
