/**
 * A mocked API for the visual tests: a small fleet with fixed data and timestamps relative to
 * NOW (the page clock is frozen there), so every screenshot is the same on every run.
 */
import type { Page, Route } from '@playwright/test';
import { readFileSync } from 'node:fs';

export const NOW = new Date('2026-06-15T14:30:00Z');
const ago = (mins: number) => new Date(NOW.getTime() - mins * 60_000).toISOString();

/** Policy sets: the built-in ones keep the server's fixed ids (the web links to All devices by id). */
const B = '00000000-0000-4000-8001-0000000000';
const SET = {
	root: `${B}00`, win: `${B}01`, linux: `${B}02`, mac: `${B}03`, winWs: `${B}11`, winSrv: `${B}12`, linWs: `${B}21`, linSrv: `${B}22`, macWs: `${B}31`, macSrv: `${B}32`,
	dc: 'ps-dc', acmeWin: 'ps-acme-win', acmeTills: 'ps-acme-tills', web01: 'ps-acme-web01'
};

const clients = [
	{ id: 'c-acme', name: 'Acme Corp', created_at: ago(60 * 24 * 200) },
	{ id: 'c-globex', name: 'Globex', created_at: ago(60 * 24 * 90) },
	{ id: 'c-initech', name: 'Initech', created_at: ago(60 * 24 * 30) },
	{ id: 'c-umbrella', name: 'Umbrella Health', created_at: ago(60 * 24 * 3) }
];
const sites = [
	{ id: 's-acme-hq', client_id: 'c-acme', name: 'Head office' },
	{ id: 's-acme-wh', client_id: 'c-acme', name: 'Warehouse' },
	{ id: 's-globex', client_id: 'c-globex', name: 'Main' },
	{ id: 's-initech', client_id: 'c-initech', name: 'Main' },
	{ id: 's-umbrella', client_id: 'c-umbrella', name: 'Clinic' }
];

function metrics(ts: string, cpu: number, mem: number, disks: [string, number][]) {
	const total = 64 * 2 ** 30;
	return {
		ts, uptime_secs: 3 * 86400 + 4 * 3600, cpu_percent: cpu, load_avg: [cpu / 25, cpu / 30, cpu / 35] as [number, number, number],
		mem_total: total, mem_used: (total * mem) / 100, swap_total: 8 * 2 ** 30, swap_used: 2 ** 29,
		disks: disks.map(([mount, used]) => ({ mount, total: 500 * 2 ** 30, available: (500 * 2 ** 30 * (100 - used)) / 100 })),
		net_rx_bytes: 1e9, net_tx_bytes: 4e8, process_count: 212
	};
}

type Agent = ReturnType<typeof agent>;
function agent(i: number, host: string, siteId: string, os: 'linux' | 'windows', online: boolean, cpu: number, mem: number, disk: number, health: string, failed = 0) {
	const s = sites.find((x) => x.id === siteId)!;
	const c = clients.find((x) => x.id === s.client_id)!;
	return {
		id: `a-${i}`, hostname: host, os_family: os, os_name: os === 'windows' ? 'Windows Server 2022' : 'Ubuntu', os_version: os === 'windows' ? 'Windows Server 2022 (21H2)' : 'Ubuntu 24.04 LTS',
		arch: 'x86_64', agent_version: '0.4.2', online, last_seen_at: online ? ago(0) : ago(37 + i * 90), enrolled_at: ago(60 * 24 * (40 - i)),
		site_id: s.id, site_name: s.name, client_id: c.id, client_name: c.name,
		last_metrics: health === 'unknown' ? null : metrics(online ? ago(0) : ago(37 + i * 90), cpu, mem, [['/', disk], ['/var', Math.max(5, disk - 30)]]),
		update_state: null, update_version: null, update_detail: null, update_at: null,
		health, disk_max_pct: health === 'unknown' ? 0 : disk, failed_jobs_24h: failed, open_alerts: 0,
		patches_overdue: 0, patches_failed: 0, reboot_pending: false, reboot_pending_since: null as string | null, alerts_muted: false,
		tags: [] as { id: string; name: string; color: string }[]
	};
}
const agents: Agent[] = [
	agent(1, 'acme-dc01', 's-acme-hq', 'windows', true, 34, 61, 72, 'healthy'),
	agent(2, 'acme-fs01', 's-acme-hq', 'windows', true, 12, 48, 96, 'unhealthy', 1),
	agent(3, 'acme-web01', 's-acme-hq', 'linux', true, 71, 83, 55, 'attention', 1),
	agent(4, 'acme-pos-07', 's-acme-wh', 'windows', false, 0, 30, 41, 'healthy'),
	agent(5, 'globex-app01', 's-globex', 'linux', true, 8, 22, 38, 'healthy'),
	agent(6, 'globex-db01', 's-globex', 'linux', true, 45, 91, 91, 'attention', 1),
	agent(7, 'initech-ws-12', 's-initech', 'windows', false, 0, 0, 0, 'unknown')
];
// One machine enrolled in the last week, so the "New" view has something to count.
agents[6].enrolled_at = ago(60 * 24 * 2);
// Patch state that counts against health, and a snoozed machine.
Object.assign(agents[2], { patches_overdue: 2, patches_failed: 1, reboot_pending: true, reboot_pending_since: ago(60 * 30) });
agents[3].alerts_muted = true;

// --- tags, custom fields, notes, saved views -----------------------------------------------------
const tagList = [
	{ id: 'tg-vip', name: 'VIP', color: 'violet', created_at: ago(60 * 24 * 30) },
	{ id: 'tg-dc', name: 'Domain controller', color: 'red', created_at: ago(60 * 24 * 30) },
	{ id: 'tg-pilot', name: 'Pilot ring', color: 'teal', created_at: ago(60 * 24 * 12) },
	{ id: 'tg-legacy', name: 'Legacy', color: 'amber', created_at: ago(60 * 24 * 9) }
];
const tagOf = (...ids: string[]) => ids.map((id) => tagList.find((t) => t.id === id)!).map(({ id, name, color }) => ({ id, name, color }));
agents[0].tags = tagOf('tg-dc', 'tg-vip');
agents[1].tags = tagOf('tg-vip');
agents[2].tags = tagOf('tg-pilot');
agents[3].tags = tagOf('tg-legacy');
const tagsOut = () => tagList.map((t) => ({ ...t, agents: agents.filter((a) => a.tags.some((x) => x.id === t.id)).length }));
const fieldDefs = [
	{ id: 'cf-warranty', entity: 'agent', name: 'warranty_end', label: 'Warranty ends', description: 'From the vendor portal', kind: 'date', options: [], client_id: null, client_name: null, script_writable: true, position: 0, in_use: 3 },
	{ id: 'cf-tier', entity: 'agent', name: 'support_tier', label: 'Support tier', description: '', kind: 'select', options: ['Gold', 'Silver', 'Bronze'], client_id: null, client_name: null, script_writable: false, position: 1, in_use: 2 },
	{ id: 'cf-owner', entity: 'agent', name: 'owner', label: 'Owner', description: 'Who uses the machine', kind: 'text', options: [], client_id: 'c-acme', client_name: 'Acme Corp', script_writable: false, position: 2, in_use: 1 },
	{ id: 'cf-am', entity: 'client', name: 'account_manager', label: 'Account manager', description: '', kind: 'text', options: [], client_id: null, client_name: null, script_writable: false, position: 0, in_use: 2 },
	{ id: 'cf-rack', entity: 'site', name: 'rack', label: 'Rack', description: 'Where the server sits', kind: 'text', options: [], client_id: null, client_name: null, script_writable: false, position: 0, in_use: 1 }
];
const fieldValues = (entity: string) =>
	fieldDefs
		.filter((f) => f.entity === entity)
		.map((f) => {
			const v: Record<string, [string, string, number]> = { cf_warranty: ['2027-03-01', 'script', 90], cf_tier: ['Gold', 'user', 600], cf_owner: ['Jo Smith', 'user', 1200], cf_am: ['Priya Nair', 'user', 3000], cf_rack: ['R12, U8', 'user', 3000] };
			const [value, source, mins] = v[f.id.replace('-', '_')] ?? [null, null, 0];
			return {
				field_id: f.id, name: f.name, label: f.label, description: f.description, kind: f.kind, options: f.options, script_writable: f.script_writable, client_id: f.client_id,
				value, source, updated_at: value ? ago(mins) : null, updated_by_name: source === 'user' ? 'Dana Admin' : null
			};
		});
const notes = [
	{ id: 'n-1', agent_id: 'a-3', body: 'Reboots itself every Sunday night: that is the patch window, not a fault.\nCall Jo at the front desk before touching it in office hours.', author_id: 'u-admin', author_name: 'Dana Admin', pinned: true, created_at: ago(60 * 24 * 6), updated_at: ago(60 * 24 * 6), can_edit: true },
	{ id: 'n-2', agent_id: 'a-3', body: 'Replaced the failing disk on the 3rd; old one is in the cupboard.', author_id: 'u-other', author_name: 'Sam Technician', pinned: false, created_at: ago(60 * 24 * 20), updated_at: ago(60 * 24 * 19), can_edit: false }
];
const savedViews = [
	{ id: 'sv-1', page: 'agents', name: 'Windows servers', shared: false, query: 'os=windows&health=attention%2Cunhealthy', hidden_columns: null, client_id: null, owner_id: 'u-admin', owner_name: 'Dana Admin', can_edit: true, created_at: ago(60 * 24 * 3), updated_at: ago(60 * 24 * 3) },
	{ id: 'sv-2', page: 'agents', name: 'VIP machines', shared: true, query: 'tag=tg-vip', hidden_columns: null, client_id: null, owner_id: 'u-other', owner_name: 'Sam Technician', can_edit: true, created_at: ago(60 * 24 * 8), updated_at: ago(60 * 24 * 8) }
];

// --- monitoring -----------------------------------------------------------------------------
const policies = [
	{ id: 'p-off', name: 'Servers offline', kind: 'offline', params: { minutes: 10 }, severity: 'critical', client_id: null, client_name: null, site_id: null, site_name: null, os_family: null, channel_ids: ['ch-mail', 'ch-teams'], notify_resolved: true, enabled: true, open_alerts: 1 },
	{ id: 'p-disk', name: 'Disk nearly full', kind: 'disk', params: { threshold: 90, minutes: 5 }, severity: 'critical', client_id: null, client_name: null, site_id: null, site_name: null, os_family: null, channel_ids: ['ch-mail'], notify_resolved: true, enabled: true, open_alerts: 2 },
	{ id: 'p-cpu', name: 'High CPU', kind: 'cpu', params: { threshold: 85, minutes: 15 }, severity: 'warning', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-hq', site_name: 'Head office', os_family: null, channel_ids: [], notify_resolved: false, enabled: true, open_alerts: 0 },
	{ id: 'p-svc', name: 'Core services', kind: 'service', params: { services: ['nginx', 'Spooler'], auto_only: true, exclude: ['sppsvc'] }, severity: 'warning', client_id: null, client_name: null, site_id: null, site_name: null, os_family: null, channel_ids: ['ch-slack'], notify_resolved: true, enabled: true, open_alerts: 1 },
	{ id: 'p-job', name: 'Backup script fails', kind: 'job_failed', params: { script_id: 's-disk' }, severity: 'warning', client_id: null, client_name: null, site_id: null, site_name: null, os_family: 'linux', channel_ids: ['ch-hook'], notify_resolved: true, enabled: true, open_alerts: 1 },
	{ id: 'p-log', name: 'Kernel OOM killer', kind: 'log', params: { min_level: 'error', sources: ['kernel'], channels: [], event_ids: [], pattern: 'out of memory' }, severity: 'info', client_id: 'c-globex', client_name: 'Globex', site_id: null, site_name: null, os_family: 'linux', channel_ids: [], notify_resolved: true, enabled: false, open_alerts: 0 }
].map((p, i) => ({
	...p, created_at: ago(60 * 24 * (30 - i)), updated_at: ago(60 * (20 - i)),
	renotify_minutes: p.id === 'p-off' ? 240 : null,
	excluded: p.id === 'p-off' ? [{ id: 'a-4', hostname: 'acme-pos-07' }] : ([] as { id: string; hostname: string }[])
}));
const pol = (id: string) => policies.find((p) => p.id === id)!;
function alert(i: number, policyId: string, agentIdx: number, title: string, opened: number, extra: Record<string, unknown> = {}) {
	const a = agents[agentIdx];
	const p = pol(policyId);
	return {
		id: `al-${i}`, policy_id: p.id, policy_name: p.name, agent_id: a.id, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name, site_name: a.site_name,
		kind: p.kind, severity: p.severity, title, details: {}, occurrences: 1, state: 'open', opened_at: ago(opened), last_seen_at: ago(1),
		acknowledged_at: null, acknowledged_by_name: null, resolved_at: null, resolved_by_name: null, resolution: null, suppressed: false, ...extra
	};
}
const alerts = [
	alert(1, 'p-disk', 1, 'Disk at or above 90% for 5 minutes', 95, { details: { value: 96.2, threshold: 90, minutes: 5 } }),
	alert(2, 'p-off', 3, 'Offline for more than 10 minutes', 47, { details: { last_seen_at: ago(127), minutes: 10 } }),
	alert(3, 'p-disk', 5, 'Disk at or above 90% for 5 minutes', 380, { state: 'acknowledged', acknowledged_at: ago(300), acknowledged_by_name: 'Terry Tech', details: { value: 91.0, threshold: 90, minutes: 5 } }),
	alert(4, 'p-svc', 2, 'Service failed: nginx.service', 22, { details: { service: 'nginx.service', state: 'failed' } }),
	alert(5, 'p-job', 2, 'Job failed: Disk usage report', 160, { occurrences: 3, details: { job_id: 'j-1', status: 'failed', exit_code: 2, script: 'Disk usage report' } }),
	alert(6, 'p-cpu', 0, 'CPU at or above 85% for 15 minutes', 60 * 26, { state: 'resolved', resolved_at: ago(60 * 25), resolution: 'cleared', details: { value: 92.4, threshold: 85, minutes: 15 } })
];
for (const a of alerts) if (a.state !== 'resolved') agents.find((x) => x.id === a.agent_id)!.open_alerts++;
const channels = [
	{ id: 'ch-mail', name: 'NOC mailbox', kind: 'email', enabled: true, policies: 2, has_secret: false, config: { to: ['noc@northwind.example', 'oncall@northwind.example'] } },
	{ id: 'ch-teams', name: 'Teams: Escalations', kind: 'teams', enabled: true, policies: 1, has_secret: false, config: { url: 'https://northwind.webhook.office.com/webhookb2/abc' } },
	{ id: 'ch-slack', name: 'Slack #alerts', kind: 'slack', enabled: true, policies: 1, has_secret: false, config: { url: 'https://hooks.slack.com/services/T000/B000/XXXX' } },
	{ id: 'ch-hook', name: 'PSA webhook', kind: 'webhook', enabled: false, policies: 1, has_secret: true, config: { url: 'https://psa.northwind.example/hooks/rmm' } },
	{ id: 'ch-page', name: 'Page on-call', kind: 'oncall', enabled: true, policies: 1, has_secret: false, config: { escalation_policy_id: 'ep-servers', when: 'outside_hours', calendar_id: 'cal-office' } },
	{ id: 'ch-pd', name: 'PagerDuty: Infrastructure', kind: 'pagerduty', enabled: true, policies: 0, has_secret: true, config: {} }
].map((c, i) => ({ ...c, created_at: ago(60 * 24 * (20 - i)) }));
// --- on-call and paging --------------------------------------------------------------------
const day0 = new Date(Date.UTC(2026, 5, 15)).getTime();
const at = (days: number, hours = 0) => new Date(day0 + (days * 24 + hours) * 3_600_000).toISOString();
const oncallPeople = [
	{ id: 'u-1', name: 'Dana Admin', email: 'dana@northwind.example', phone_verified: true },
	{ id: 'u-2', name: 'Terry Tech', email: 'terry@northwind.example', phone_verified: true },
	{ id: 'u-4', name: 'Priya Nair', email: 'priya@northwind.example', phone_verified: false }
];
const oncallSchedules = [
	{
		id: 'os-1', name: 'Out of hours', timezone: 'Europe/London',
		layers: [
			{ id: 'ol-1', position: 0, name: 'Weekly', user_ids: ['u-2', 'u-4'], start_at: at(-7, 9), shift_hours: 168, restrict: [] },
			{ id: 'ol-2', position: 1, name: 'Weekdays', user_ids: ['u-1'], start_at: at(-7, 0), shift_hours: 24, restrict: [{ days: [0, 1, 2, 3, 4], start: 540, end: 1020 }] }
		],
		overrides: [{ id: 'oo-1', schedule_id: 'os-1', user_id: 'u-4', user_name: 'Priya Nair', starts_at: at(2, 17), ends_at: at(3, 9) }],
		now: { schedule_id: 'os-1', schedule_name: 'Out of hours', user_id: 'u-1', user_name: 'Dana Admin', until: at(0, 17), source: 'layer' }
	},
	{ id: 'os-2', name: 'Security', timezone: 'UTC', layers: [], overrides: [], now: { schedule_id: 'os-2', schedule_name: 'Security', user_id: null, user_name: null, until: null, source: null } }
];
const seg = (user_id: string, start: string, end: string) => ({ user_id, user_name: oncallPeople.find((p) => p.id === user_id)!.name, start, end });
const weekdays = [0, 1, 2, 3, 4].map((d) => seg('u-1', at(d, 9), at(d, 17)));
const oncallShifts = {
	from: at(0), to: at(7), timezone: 'Europe/London',
	layers: [
		{ id: 'ol-1', name: 'Weekly', position: 0, segments: [seg('u-2', at(0), at(0, 9)), seg('u-4', at(0, 9), at(7))] },
		{ id: 'ol-2', name: 'Weekdays', position: 1, segments: weekdays }
	],
	overrides: [seg('u-4', at(2, 17), at(3, 9))],
	final: [
		seg('u-2', at(0), at(0, 9)), seg('u-1', at(0, 9), at(0, 17)), seg('u-4', at(0, 17), at(1, 9)), seg('u-1', at(1, 9), at(1, 17)), seg('u-4', at(1, 17), at(2, 9)),
		seg('u-1', at(2, 9), at(2, 17)), seg('u-4', at(2, 17), at(3, 9)), seg('u-1', at(3, 9), at(3, 17)), seg('u-4', at(3, 17), at(4, 9)), seg('u-1', at(4, 9), at(4, 17)), seg('u-4', at(4, 17), at(7))
	]
};
const escalationPolicies = [
	{
		id: 'ep-servers', name: 'Servers, out of hours', repeat: 1,
		steps: [
			{ delay_minutes: 10, targets: [{ schedule: 'os-1' }] },
			{ delay_minutes: 15, targets: [{ user: 'u-1' }, { channel: 'ch-teams' }] }
		],
		channels: [{ id: 'ch-page', name: 'Page on-call' }]
	}
];
const oncallPages = [
	{
		id: 'pg-1', alert_id: 'al-5', ticket_id: null, title: 'Job failed: Disk usage report on acme-web01', severity: 'warning', status: 'acknowledged', step: 1, round: 0,
		policy_name: 'Servers, out of hours', acked_by_name: 'Dana Admin', acked_at: ago(140), resolved_at: null, created_at: ago(160), next_escalation_at: null,
		deliveries: [
			{ id: 'pd-1', user_name: 'Terry Tech', channel_name: null, method: 'push', step: 0, round: 0, status: 'sent', attempts: 1, error: null, created_at: ago(160), sent_at: ago(160), next_attempt_at: ago(160) },
			{ id: 'pd-2', user_name: 'Terry Tech', channel_name: null, method: 'sms', step: 0, round: 0, status: 'sent', attempts: 1, error: null, created_at: ago(160), sent_at: ago(160), next_attempt_at: ago(160) },
			{ id: 'pd-3', user_name: 'Dana Admin', channel_name: null, method: 'sms', step: 1, round: 0, status: 'sent', attempts: 1, error: null, created_at: ago(150), sent_at: ago(150), next_attempt_at: ago(150) },
			{ id: 'pd-4', user_name: null, channel_name: 'Teams: Escalations', method: 'channel', step: 1, round: 0, status: 'sent', attempts: 0, error: null, created_at: ago(150), sent_at: ago(150), next_attempt_at: ago(150) },
			{ id: 'pd-5', user_name: 'Dana Admin', channel_name: null, method: 'email', step: 1, round: 0, status: 'cancelled', attempts: 0, error: null, created_at: ago(150), sent_at: null, next_attempt_at: ago(145) }
		]
	}
];
const notificationPrefs = {
	hide_details: false,
	events: [
		{ event: 'page', label: "I'm paged", push: true, email: true, email_applies: false },
		{ event: 'alert_critical', label: 'Critical alerts', push: true, email: true, email_applies: false },
		{ event: 'alert_warning', label: 'Warnings', push: false, email: true, email_applies: false },
		{ event: 'ticket_assigned', label: 'A ticket is assigned to me', push: true, email: true, email_applies: true },
		{ event: 'ticket_reply', label: 'A client replies on my ticket', push: false, email: true, email_applies: true },
		{ event: 'sla_warning', label: 'SLA warnings and breaches on my tickets', push: false, email: false, email_applies: true }
	]
};

const deliveries = [
	{ id: 9, channel_id: 'ch-mail', channel_name: 'NOC mailbox', alert_id: 'al-4', alert_title: 'Service failed: nginx.service', hostname: 'acme-web01', event: 'opened', status: 'sent', attempts: 1, last_error: null, created_at: ago(22), sent_at: ago(22), next_attempt_at: ago(12) },
	{ id: 8, channel_id: 'ch-hook', channel_name: 'PSA webhook', alert_id: 'al-5', alert_title: 'Job failed: Disk usage report', hostname: 'acme-web01', event: 'opened', status: 'failed', attempts: 5, last_error: 'HTTP 502 Bad Gateway: upstream unavailable', created_at: ago(160), sent_at: null, next_attempt_at: ago(10) },
	{ id: 7, channel_id: 'ch-teams', channel_name: 'Teams: Escalations', alert_id: 'al-2', alert_title: 'Offline for more than 10 minutes', hostname: 'acme-pos-07', event: 'opened', status: 'pending', attempts: 2, last_error: 'request failed: connection timed out', created_at: ago(47), sent_at: null, next_attempt_at: ago(-3) },
	{ id: 6, channel_id: 'ch-mail', channel_name: 'NOC mailbox', alert_id: null, alert_title: null, hostname: null, event: 'test', status: 'sent', attempts: 1, last_error: null, created_at: ago(900), sent_at: ago(900), next_attempt_at: ago(900) }
];
const services = [
	['cron.service', 'Regular background program processing daemon', 'running', 'auto'],
	['nginx.service', 'A high performance web server and a reverse proxy server', 'failed', 'auto'],
	['ssh.service', 'OpenBSD Secure Shell server', 'running', 'auto'],
	['postgresql.service', 'PostgreSQL RDBMS', 'running', 'auto'],
	['rsync.service', 'fast remote file copy program daemon', 'stopped', 'disabled'],
	['systemd-journald.service', 'Journal Service', 'running', 'manual'],
	['unattended-upgrades.service', 'Unattended Upgrades Shutdown', 'stopped', 'auto'],
	['apt-daily.service', 'Daily apt download activities', 'stopped', 'manual']
].map(([name, display_name, state, start_mode]) => ({ name, display_name, state, start_mode }));
const logEvents = [
	{ id: 31, ts: ago(14), level: 'error', source: 'kernel', event_id: null, message: 'Out of memory: Killed process 48211 (php-fpm8.2) total-vm:1834552kB, anon-rss:912340kB, file-rss:0kB, shmem-rss:2048kB, UID:33 pgtables:2140kB oom_score_adj:0', policy_name: 'Kernel OOM killer', alert_id: null },
	{ id: 30, ts: ago(71), level: 'critical', source: 'nginx.service', event_id: null, message: 'nginx.service: Main process exited, code=exited, status=1/FAILURE', policy_name: 'Kernel OOM killer', alert_id: null },
	{ id: 29, ts: ago(240), level: 'error', source: 'kernel', event_id: null, message: 'Out of memory: Killed process 1022 (node)', policy_name: 'Kernel OOM killer', alert_id: null }
];
const schedules = [
	{ id: 'sc-1', name: 'Nightly disk report', set_id: SET.linux, script_id: 's-disk', script_name: 'Disk usage report', interpreter: 'bash', client_id: null, client_name: null, site_id: null, site_name: null, cron: '0 2 * * *', timezone: 'Europe/London', args: [], timeout_secs: null, retain_days: 30, enabled: true, agents: 3, next_run_at: ago(-60 * 11 - 30), last_run_at: ago(60 * 12 + 30), last_run: { succeeded: 3, failed: 1 } },
	{ id: 'sc-2', name: 'Clear print queue', set_id: SET.win, script_id: 's-spool', script_name: 'Restart print spooler', interpreter: 'powershell', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-wh', site_name: 'Warehouse', cron: '30 6 * * 1-5', timezone: 'America/Chicago', args: [], timeout_secs: 120, retain_days: 7, enabled: true, agents: 1, next_run_at: ago(-60 * 21), last_run_at: ago(60 * 3), last_run: { succeeded: 1, queued: 1 } },
	{ id: 'sc-3', name: 'Weekly update check', set_id: SET.root, script_id: 's-upd', script_name: 'Pending updates', interpreter: 'python', client_id: null, client_name: null, site_id: null, site_name: null, cron: '0 3 * * 0', timezone: 'UTC', args: ['--security'], timeout_secs: 600, retain_days: 90, enabled: false, agents: 7, next_run_at: ago(-60 * 24 * 3), last_run_at: null, last_run: {} }
].map((s, i) => ({ ...s, created_by_name: 'Dana Admin', created_at: ago(60 * 24 * (40 - i)), updated_at: ago(60 * 24 * (5 - i)) }));
const mutes = [
	{ id: 'm-1', client_id: null, site_id: null, agent_id: 'a-4', owner_client_id: 'c-acme', target_name: 'acme-pos-07', starts_at: null, ends_at: ago(-60 * 3), days: null, start_time: null, minutes: null, tz: 'UTC', reason: 'Replacing the till', created_by_name: 'Terry Tech', created_at: ago(60), active: true, ended: false },
	{ id: 'm-2', client_id: null, site_id: 's-acme-wh', agent_id: null, owner_client_id: 'c-acme', target_name: 'Acme Corp › Warehouse', starts_at: null, ends_at: null, days: [6, 0], start_time: '22:00:00', minutes: 360, tz: 'America/Chicago', reason: 'Weekend patching', created_by_name: 'Dana Admin', created_at: ago(60 * 24 * 9), active: false, ended: false }
];
const processes = [
	[1, null, 'systemd', 'root', 0.1, 14, true, '/sbin/init splash'],
	[812, 1, 'sshd', 'root', 0, 9, false, 'sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups'],
	[1204, 1, 'nginx', 'root', 0.4, 12, false, 'nginx: master process /usr/sbin/nginx -g daemon on; master_process on;'],
	[1205, 1204, 'nginx', 'www-data', 3.2, 48, false, 'nginx: worker process'],
	[2210, 1, 'postgres', 'postgres', 7.9, 412, false, '/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main'],
	[3120, 1, 'php-fpm8.2', 'www-data', 41.5, 920, false, 'php-fpm: pool www'],
	[4410, 1, 'rmm-agent', 'root', 0.2, 11, true, '/usr/local/bin/rmm-agent --config /etc/rmm/agent.toml run']
].map(([pid, ppid, name, user, cpu, mb, prot, cmd]) => ({ pid, ppid, name, user, cpu, mem: (mb as number) * 2 ** 20, protected: prot, cmd, exe: null, started_at: ago(60 * 24 * 3 - (pid as number) / 100) }));
function listing(path: string) {
	if (!path) return { path: '', parent: null, truncated: false, entries: [{ name: '/', path: '/', dir: true, symlink: false, size: 0, modified: null, error: null }] };
	const entries = [
		['nginx', true, 0, 60 * 24 * 12], ['postgresql', true, 0, 60 * 24 * 2], ['auth.log', false, 482_113, 3], ['syslog', false, 18_442_901, 1],
		['syslog.1', false, 52_118_004, 60 * 24], ['dpkg.log', false, 1_204_551, 60 * 30], ['kern.log', false, 88_120, 60 * 5]
	].map(([name, dir, size, mins]) => ({ name, path: `${path.replace(/\/$/, '')}/${name}`, dir, symlink: false, size, modified: ago(mins as number), error: null }));
	return { path, parent: path === '/' ? '' : path.replace(/\/[^/]+$/, '') || '/', truncated: false, entries };
}
const detail = (a: Agent) => ({
	...a,
	kernel_version: a.os_family === 'windows' ? '10.0.20348' : '6.8.0-45-generic',
	machine_id: 'm-' + a.id,
	// globex-db01 runs an agent build without remote desktop.
	capabilities: a.id === 'a-6' ? ['patch'] : ['patch', 'desktop', 'tools'],
	pinned_note: a.id === 'a-3' ? notes[0] : null,
	inventory_at: ago(12),
	inventory: {
		collected_at: ago(12), cpu_brand: 'Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz', cpu_cores_physical: 16, cpu_cores_logical: 32, mem_total: 64 * 2 ** 30,
		disks: [
			{ name: '/dev/sda1', mount: '/', fs: 'ext4', kind: 'SSD', removable: false, total: 500 * 2 ** 30 },
			{ name: '/dev/sdb1', mount: '/var', fs: 'xfs', kind: 'HDD', removable: false, total: 500 * 2 ** 30 }
		],
		network: [{ name: 'eth0', mac: '00:15:5d:01:02:03', addrs: ['10.0.4.21/24', 'fe80::215:5dff:fe01:203/64'] }],
		software: Array.from({ length: 14 }, (_, i) => ({
			name: ['7-Zip', 'Google Chrome', 'Microsoft Edge', 'Notepad++', 'OpenSSH', 'PowerShell 7', 'Python 3.12', 'Git', 'VLC', 'Zoom', 'curl', 'nginx', 'openssl', 'rsync'][i],
			version: `${(i % 5) + 1}.${i}.${i * 3}`, publisher: i % 3 ? 'Vendor Inc.' : null, source: a.os_family === 'windows' ? 'registry' : 'dpkg'
		})),
		logged_in_users: a.online ? ['jsmith'] : []
	}
});

const statuses = ['succeeded', 'failed', 'succeeded', 'sent', 'succeeded', 'timed_out', 'queued', 'succeeded', 'lost', 'succeeded'];
const jobs = statuses.map((status, i) => {
	const a = agents[i % 6];
	const done = !['queued', 'sent'].includes(status);
	return {
		id: `j-${i}`, agent_id: a.id, hostname: a.hostname, script_id: i % 3 ? 's-disk' : null, script_name: i % 3 ? 'Disk usage report' : null,
		interpreter: a.os_family === 'windows' ? 'powershell' : 'bash', status, exit_code: done ? (status === 'succeeded' ? 0 : status === 'failed' ? 2 : null) : null,
		created_by_name: 'Dana Admin', created_at: ago(5 + i * 41), sent_at: status === 'queued' ? null : ago(5 + i * 41), finished_at: done ? ago(4 + i * 41) : null,
		duration_ms: done ? 830 + i * 1300 : null, schedule_id: i === 2 ? 'sc-1' : null, schedule_name: i === 2 ? 'Nightly disk report' : null
	};
});
const jobDetail = (j: (typeof jobs)[number]) => ({
	...j, body: 'df -h --output=target,pcent | sort -k2 -rn', args: [], timeout_secs: 300,
	params: j.id === 'j-1' ? { min_pct: 95, notify: 'ops@acme.example', token: '•••' } : {},
	stdout: 'Mounted on Use%\n/          96%\n/var       66%\n/boot      12%\n', stderr: j.status === 'failed' ? 'warning: / is above 95%\n' : '',
	stdout_len: 62, stderr_len: j.status === 'failed' ? 25 : 0
});
const scripts = [
	{ id: 's-disk', name: 'Disk usage report', description: 'Free space per mount, fullest first', interpreter: 'bash', body: 'df -h --output=target,pcent | sort -k2 -rn', timeout_secs: 120, client_id: null, client_name: null,
		params: [{ name: 'min_pct', label: 'Warn above (%)', type: 'number', required: false, default: 90, description: 'Mounts fuller than this are listed first' }], created_at: ago(9000), updated_at: ago(2000) },
	{ id: 's-spool', name: 'Restart print spooler', description: 'Clears stuck print jobs', interpreter: 'powershell', body: 'Stop-Service Spooler -Force\nRemove-Item C:\\Windows\\System32\\spool\\PRINTERS\\* -Force\nStart-Service Spooler', timeout_secs: 60, client_id: 'c-acme', client_name: 'Acme Corp',
		params: [
			{ name: 'printer', label: 'Printer', type: 'text', required: true, description: 'Queue to clear, or * for all' },
			{ name: 'mode', label: 'Mode', type: 'select', required: false, default: 'safe', choices: ['safe', 'force'], description: '' },
			{ name: 'notify', label: 'Notify when done', type: 'bool', required: false, default: false, description: '' },
			{ name: 'admin_password', label: 'Print server admin', type: 'secret', required: false, description: 'Only for remote queues' }
		], created_at: ago(8000), updated_at: ago(300) },
	{ id: 's-upd', name: 'Pending updates', description: '', interpreter: 'python', body: 'import subprocess\nprint(subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True).stdout)', timeout_secs: 300, client_id: null, client_name: null, params: [], created_at: ago(7000), updated_at: ago(7000) }
];

const page = <T>(items: T[], limit = 1000) => ({ items: items.slice(0, limit), next: null, prev: null, total: items.length, total_exact: true });
function clientOut(c: (typeof clients)[number]) {
	return {
		...c,
		email_domains: c.id === 'c-acme' ? ['acme.example'] : [],
		security_canary: c.id === 'c-initech',
		sites: sites.filter((s) => s.client_id === c.id).map((s) => {
			const as = agents.filter((a) => a.site_id === s.id);
			return { ...s, agent_count: as.length, online_count: as.filter((a) => a.online).length };
		})
	};
}
function clientHealth() {
	return clients
		.map((c) => {
			const as = agents.filter((a) => a.client_id === c.id);
			return {
				id: c.id, name: c.name, agents: as.length, online: as.filter((a) => a.online).length,
				attention: as.filter((a) => a.health === 'attention').length, unhealthy: as.filter((a) => a.health === 'unhealthy').length,
				failed_jobs_24h: as.reduce((n, a) => n + a.failed_jobs_24h, 0), open_alerts: as.reduce((n, a) => n + a.open_alerts, 0)
			};
		})
		.sort((a, b) => b.unhealthy - a.unhealthy || b.attention - a.attention || a.name.localeCompare(b.name));
}
function dashboard(clientId: string | null) {
	const as = agents.filter((a) => !clientId || a.client_id === clientId);
	const count = (h: string) => as.filter((a) => a.health === h).length;
	return {
		agents_total: as.length, agents_online: as.filter((a) => a.online).length, clients: clientId ? 1 : clients.length,
		by_os: { windows: as.filter((a) => a.os_family === 'windows').length, linux: as.filter((a) => a.os_family === 'linux').length },
		health: { healthy: count('healthy'), attention: count('attention'), unhealthy: count('unhealthy'), unknown: count('unknown') },
		jobs_24h: { succeeded: 5, failed: 1, timed_out: 1, lost: 1, sent: 1, queued: 1 },
		offline: as.filter((a) => !a.online), high_disk: as.filter((a) => a.disk_max_pct >= 90).sort((a, b) => b.disk_max_pct - a.disk_max_pct),
		failed_jobs: jobs.filter((j) => ['failed', 'timed_out', 'lost'].includes(j.status)), client_health: clientHealth().filter((c) => !clientId || c.id === clientId),
		alerts: alertSummary(clientId), open_alerts: alerts.filter((a) => a.state !== 'resolved' && (!clientId || a.client_id === clientId))
	};
}
function alertSummary(clientId: string | null) {
	const out: Record<string, number> = {};
	for (const a of alerts) if (a.state !== 'resolved' && (!clientId || a.client_id === clientId)) out[a.severity] = (out[a.severity] ?? 0) + 1;
	return out;
}

/** A day of samples that ends at the agent's current numbers, so the charts agree with the meters. */
function metricHistory(a: Agent) {
	const n = 96;
	const m = a.last_metrics;
	const cpuNow = m?.cpu_percent ?? 0;
	const memNow = m ? (100 * m.mem_used) / m.mem_total : 0;
	const total = 64 * 2 ** 30;
	return Array.from({ length: n }, (_, i) => {
		const k = i / (n - 1);
		const wave = (amp: number, f: number) => amp * Math.sin(i / f) * (1 - k); // fades out toward "now"
		const cpu = Math.min(100, Math.max(1, cpuNow + wave(18, 8) + ((i * 37) % 13) * (1 - k)));
		const mem = Math.min(100, Math.max(1, memNow + wave(6, 20)));
		const disk = Math.max(1, a.disk_max_pct - (1 - k) * 6);
		return { ts: new Date(NOW.getTime() - (n - 1 - i) * 15 * 60_000).toISOString(), cpu_percent: cpu, mem_used: (mem / 100) * total, mem_total: total, disk_max_pct: disk, net_rx_bytes: 1e9, net_tx_bytes: 4e8 };
	});
}


// Patch management: a few Windows updates and Linux packages spread over the fleet.
const updates = [
	{ update_id: 'b3c1d2e4-0001', title: '2026-06 Cumulative Update for Windows Server 2022 (KB5060526)', kb: 'KB5060526', severity: 'critical', category: 'security', size: 812_000_000, requires_reboot: true, on: ['a-1', 'a-2', 'a-4'], installedOn: [] as string[] },
	{ update_id: 'openssl', title: 'openssl 3.0.13-0ubuntu3.5', kb: null, severity: null, category: 'security', size: 1_441_784, requires_reboot: false, on: ['a-3', 'a-5', 'a-6'], installedOn: [] },
	{ update_id: 'b3c1d2e4-0002', title: 'Security Intelligence Update for Microsoft Defender Antivirus (KB2267602)', kb: 'KB2267602', severity: null, category: 'definition', size: 68_000_000, requires_reboot: false, on: ['a-1', 'a-2'], installedOn: ['a-4'] },
	{ update_id: 'curl', title: 'curl 8.5.0-2ubuntu10.6', kb: null, severity: null, category: 'update', size: 226_334, requires_reboot: false, on: ['a-3', 'a-6'], installedOn: ['a-5'] },
	{ update_id: 'b3c1d2e4-0003', title: 'Intel - Net - 1.2.3.4', kb: null, severity: null, category: 'driver', size: 4_200_000, requires_reboot: true, on: ['a-2'], installedOn: [] },
	{ update_id: 'linux-image-6.8.0-60-generic', title: 'linux-generic 6.8.0.60.60', kb: null, severity: null, category: 'security', size: 15_000_000, requires_reboot: true, on: ['a-3'], installedOn: [] }
];
const approvalOf = (u: (typeof updates)[number], agentId: string) =>
	u.category === 'driver' ? 'declined' : u.category === 'update' && agentId !== 'a-6' ? 'pending' : 'approved';
const stateOf = (u: (typeof updates)[number], agentId: string) => (u.installedOn.includes(agentId) ? 'installed' : u.update_id === 'curl' && agentId === 'a-6' ? 'failed' : 'missing');
function updateGroups() {
	return updates.map(({ on, installedOn, ...u }) => {
		const appr = on.map((a) => approvalOf({ ...u, on, installedOn }, a));
		return {
			...u, missing: on.length, installed: installedOn.length, failed: u.update_id === 'curl' ? 1 : 0, installing: 0,
			approved: appr.filter((x) => x === 'approved').length, pending: appr.filter((x) => x === 'pending').length,
			declined: appr.filter((x) => x === 'declined').length, first_seen_at: ago(60 * 24 * 3 + u.title.length)
		};
	});
}
const windowRow = (s: (typeof sites)[number]) => {
	const set = s.client_id === 'c-acme';
	return {
		site_id: s.id, site_name: s.name, client_id: s.client_id, client_name: clients.find((c) => c.id === s.client_id)!.name,
		days: set ? (s.id === 's-acme-wh' ? [0] : [6]) : null, start: set ? '02:00' : null, minutes: set ? 180 : null, tz: set ? 'Europe/London' : 'UTC',
		open_now: !set, next_start: set ? new Date(Date.parse('2026-06-20T01:00:00Z') + (s.id === 's-acme-wh' ? 86_400_000 : 0)).toISOString() : null,
		agents: agents.filter((a) => a.site_id === s.id).length
	};
};
const runs = [
	{ id: 'r-1', agent: 'a-3', status: 'sent', stage: 'installing', progress: 'setting up openssl', percent: 64, updates: 2, succeeded: 0, trigger: 'manual', created: 3, finished: null as number | null },
	{ id: 'r-2', agent: 'a-1', status: 'succeeded', stage: null, progress: null, percent: null, updates: 2, succeeded: 2, trigger: 'policy', created: 60 * 20, finished: 60 * 20 - 34, reboot_required: true, rebooting: true },
	{ id: 'r-3', agent: 'a-6', status: 'partial', stage: null, progress: null, percent: null, updates: 3, succeeded: 2, trigger: 'policy', created: 60 * 22, finished: 60 * 22 - 4, error: null },
	{ id: 'r-4', agent: 'a-4', status: 'queued', stage: null, progress: null, percent: null, updates: 1, succeeded: 0, trigger: 'manual', created: 60 * 2, finished: null },
	{ id: 'r-5', agent: 'a-2', status: 'failed', stage: null, progress: null, percent: null, updates: 1, succeeded: 0, trigger: 'policy', created: 60 * 46, finished: 60 * 46 - 12, error: 'Windows must restart before this update can install' }
].map((r) => {
	const a = agents.find((x) => x.id === r.agent)!;
	return {
		id: r.id, agent_id: a.id, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name, trigger: r.trigger, created_by_name: r.trigger === 'manual' ? 'Dana Admin' : null,
		status: r.status, stage: r.stage, progress: r.progress, percent: r.percent, error: (r as { error?: string | null }).error ?? null, updates: r.updates, succeeded: r.succeeded,
		reboot_policy: r.trigger === 'policy' ? 'if_required' : 'never', reboot_required: (r as { reboot_required?: boolean }).reboot_required ?? false, rebooting: (r as { rebooting?: boolean }).rebooting ?? false,
		created_at: ago(r.created), sent_at: r.status === 'queued' ? null : ago(r.created), finished_at: r.finished == null ? null : ago(r.finished), duration_ms: r.finished == null ? null : (r.created - r.finished) * 60_000
	};
});

// --- software deployment ---------------------------------------------------------------------------------
const swPackages = [
	{ id: 'sw-ff', client_id: null, client_name: null, name: 'Mozilla Firefox', description: 'The browser, from winget, Chocolatey and apt.', publisher: 'Mozilla', winget_id: 'Mozilla.Firefox', choco_id: 'firefox', apt_name: 'firefox', dnf_name: 'firefox', version: null as string | null, installer: null as null | { name: string; kind: 'msi' | 'exe'; size: number; sha256: string }, silent_args: '', uninstall_cmd: null, product_code: null, detect_name: null, platforms: ['windows', 'linux'], installed_on: 3, updates: 2, policies: 1, created_at: ago(60 * 24 * 40), updated_at: ago(60 * 24 * 3) },
	{ id: 'sw-7z', client_id: null, client_name: null, name: '7-Zip', description: '', publisher: 'Igor Pavlov', winget_id: '7zip.7zip', choco_id: '7zip', apt_name: null, dnf_name: null, version: '23.01', installer: null, silent_args: '', uninstall_cmd: null, product_code: null, detect_name: null, platforms: ['windows'], installed_on: 2, updates: 0, policies: 0, created_at: ago(60 * 24 * 30), updated_at: ago(60 * 24 * 30) },
	{ id: 'sw-crm', client_id: 'c-acme', client_name: 'Acme Corp', name: 'Acme CRM agent', description: 'Line-of-business app, uploaded MSI.', publisher: 'Acme IT', winget_id: null, choco_id: null, apt_name: null, dnf_name: null, version: '4.2.1', installer: { name: 'AcmeCRM-4.2.1.msi', kind: 'msi' as const, size: 48_220_160, sha256: 'c4'.repeat(32) }, silent_args: 'SERVER=crm.acme.test', uninstall_cmd: null, product_code: '{4C1D7A52-0E6B-4F0A-9A34-2B8C5E7D1F93}', detect_name: null, platforms: ['windows'], installed_on: 1, updates: 0, policies: 0, created_at: ago(60 * 24 * 12), updated_at: ago(60 * 24 * 2) },
	{ id: 'sw-new', client_id: null, client_name: null, name: 'Vendor tool (installer to come)', description: '', publisher: null, winget_id: null, choco_id: null, apt_name: null, dnf_name: null, version: null, installer: null, silent_args: '', uninstall_cmd: null, product_code: null, detect_name: null, platforms: [], installed_on: 0, updates: 0, policies: 0, created_at: ago(60), updated_at: ago(60) }
];
const swDev = (agent: string, pkg: string, o: Record<string, unknown>) => {
	const a = agents.find((x) => x.id === agent)!;
	const p = swPackages.find((x) => x.id === pkg)!;
	return { agent_id: a.id, hostname: a.hostname, os_family: a.os_family, online: a.online, client_id: a.client_id, client_name: a.client_name, site_name: a.site_name, package_id: p.id, package_name: p.name, pin: p.version,
		installed: null as string | null, available: null as string | null, ignored: null as string | null, provider: 'winget' as string | null, checked_at: ago(95), desired: null as string | null, policy_items: [] as string[], compliant: null as boolean | null, last_run: null as unknown, fail_count: 0, last_error: null as string | null, ...o };
};
const swDevices = [
	swDev('a-1', 'sw-ff', { installed: '124.0.1', available: '125.0.3', desired: 'latest', policy_items: ['sw-req'], compliant: false }),
	swDev('a-3', 'sw-ff', { installed: '124.0.1', available: '125.0.3', provider: 'apt', desired: 'latest', policy_items: ['sw-req'], compliant: false }),
	swDev('a-2', 'sw-ff', { installed: '125.0.3', desired: 'latest', policy_items: ['sw-req'], compliant: true }),
	swDev('a-1', 'sw-7z', { installed: '23.01' }),
	swDev('a-2', 'sw-7z', { installed: null, desired: 'present', policy_items: ['sw-req-7z'], compliant: false, fail_count: 2, last_error: 'winget install failed (exit 0x8a150010): No applicable installer found', last_run: { id: 'sr-2', op: 'install', status: 'failed', trigger: 'policy', at: ago(40), error: 'winget install failed (exit 0x8a150010): No applicable installer found' } }),
	swDev('a-1', 'sw-crm', { installed: '4.2.0', available: '4.2.1', provider: 'installer', desired: 'present', policy_items: ['sw-req-crm'], compliant: false })
];
const swRuns = [
	{ id: 'sr-1', agent_id: 'a-1', package_id: 'sw-ff', package_name: 'Mozilla Firefox', op: 'upgrade', trigger: 'policy', policy_item_id: 'sw-req', created_by_name: null, status: 'sent', stage: 'installing', progress: 'winget upgrade Mozilla.Firefox', error: null, provider: null, from_version: '124.0.1', to_version: null, reboot_required: false, created: 3, finished: null as number | null, duration_ms: null as number | null },
	{ id: 'sr-2', agent_id: 'a-2', package_id: 'sw-7z', package_name: '7-Zip', op: 'install', trigger: 'policy', policy_item_id: 'sw-req-7z', created_by_name: null, status: 'failed', stage: null, progress: null, error: 'winget install failed (exit 0x8a150010): No applicable installer found', provider: 'winget', from_version: null, to_version: null, reboot_required: false, created: 40, finished: 39, duration_ms: 41_000 },
	{ id: 'sr-3', agent_id: 'a-3', package_id: 'sw-ff', package_name: 'Mozilla Firefox', op: 'install', trigger: 'manual', policy_item_id: null, created_by_name: 'Dana Admin', status: 'succeeded', stage: null, progress: null, error: null, provider: 'apt', from_version: null, to_version: '124.0.1', reboot_required: false, created: 60 * 26, finished: 60 * 26 - 1, duration_ms: 52_000 },
	{ id: 'sr-4', agent_id: 'a-1', package_id: 'sw-crm', package_name: 'Acme CRM agent', op: 'upgrade', trigger: 'manual', policy_item_id: null, created_by_name: 'Dana Admin', status: 'queued', stage: null, progress: null, error: null, provider: null, from_version: '4.2.0', to_version: null, reboot_required: false, created: 8, finished: null, duration_ms: null }
].map((r) => {
	const a = agents.find((x) => x.id === r.agent_id)!;
	const { created, finished, ...rest } = r;
	return { ...rest, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name, created_at: ago(created), sent_at: r.status === 'queued' ? null : ago(created), finished_at: finished == null ? null : ago(finished), output: r.status === 'sent' ? '' : '$ winget install --exact --id 7zip.7zip --source winget --silent\nNo applicable installer found; see logs for more details.\n[exit -1978335216]\n' };
});
function agentSoftware(a: Agent) {
	return {
		capable: a.id !== 'a-7', providers: a.os_family === 'windows' ? ['winget', 'choco', 'installer'] : ['apt'], scanned_at: ago(95), scan_requested_at: null, scan_error: null,
		items: swDevices.filter((d) => d.agent_id === a.id), runs: swRuns.filter((r) => r.agent_id === a.id)
	};
}
function agentPatches(a: Agent) {
	const rows = updates.filter((u) => u.on.includes(a.id) || u.installedOn.includes(a.id)).map((u) => ({
		update_id: u.update_id, title: u.title, kb: u.kb, severity: u.severity, category: u.category, size: u.size, requires_reboot: u.requires_reboot,
		version: a.os_family === 'linux' ? u.title.split(' ')[1] : null, current_version: a.os_family === 'linux' ? '3.0.13-0ubuntu3.1' : null,
		state: stateOf(u, a.id), approval: approvalOf(u, a.id), approval_manual: u.category === 'driver', approved_by_name: u.category === 'driver' ? 'Dana Admin' : null,
		approved_at: ago(600), first_seen_at: ago(60 * 24 * 3), installed_at: u.installedOn.includes(a.id) ? ago(60 * 20) : null,
		last_error: stateOf(u, a.id) === 'failed' ? 'apt-get failed: E: Could not get lock /var/lib/dpkg/lock-frontend' : null, fail_count: stateOf(u, a.id) === 'failed' ? 1 : 0,
		deferred_until: a.client_id === 'c-acme' && u.category === 'security' && u.severity !== 'critical' ? ago(-60 * 24) : null
	}));
	const site = sites.find((s) => s.id === a.site_id)!;
	return {
		status: { supported: a.id !== 'a-7', online: a.online, os_family: a.os_family, provider: a.os_family === 'windows' ? 'wua' : 'apt', all_or_nothing: false,
			scanned_at: a.id === 'a-7' ? null : ago(95), scan_requested_at: null, scan_error: null, reboot_pending: a.id === 'a-1' },
		policy: agentPatchPolicy(a, windowRow(site)),
		window: windowRow(site), patches: rows, runs: runs.filter((r) => r.agent_id === a.id)
	};
}
function compliance(clientId: string | null) {
	const rows = (clientId ? sites.filter((s) => s.client_id === clientId) : clients).map((g) => {
		const as = agents.filter((a) => (clientId ? a.site_id === g.id : a.client_id === g.id));
		const scanned = as.filter((a) => a.id !== 'a-7');
		const missing = (a: Agent) => updates.filter((u) => u.on.includes(a.id) && approvalOf(u, a.id) !== 'declined');
		return {
			id: g.id, name: g.name, client_id: clientId, agents: as.length, supported: scanned.length, scanned: scanned.length,
			compliant: scanned.filter((a) => missing(a).length === 0).length, missing: scanned.reduce((n, a) => n + missing(a).length, 0),
			agents_missing_security: scanned.filter((a) => missing(a).some((u) => u.category === 'security')).length, failed: as.some((a) => a.id === 'a-6') ? 1 : 0,
			reboot_pending: as.filter((a) => a.id === 'a-1').length, scan_errors: 0, installed_30d: as.length * 3, oldest_scan: scanned.length ? ago(95) : null
		};
	}).sort((x, y) => (x.scanned ? x.compliant / x.scanned : 2) - (y.scanned ? y.compliant / y.scanned : 2));
	const sum = (k: keyof (typeof rows)[number]) => rows.reduce((n, r) => n + (r[k] as number), 0);
	return { by: clientId ? 'site' : 'client', rows, totals: Object.fromEntries(['agents', 'supported', 'scanned', 'compliant', 'missing', 'agents_missing_security', 'failed', 'reboot_pending', 'scan_errors', 'installed_30d'].map((k) => [k, sum(k as keyof (typeof rows)[number])])) };
}

// --- service desk ---------------------------------------------------------------------------
const boardStatuses = (b: string) =>
	[['New', 'new'], ['In progress', 'open'], ['Waiting on client', 'waiting_client'], ['Waiting on vendor', 'waiting_vendor'], ['Resolved', 'resolved'], ['Closed', 'closed']].map(
		([name, category], position) => ({ id: `${b}-st-${category}`, name, category, position })
	);
const boards = [
	{ id: 'b-desk', name: 'Service Desk', description: 'Requests and incidents from clients.', position: 0, statuses: boardStatuses('b-desk'), open_tickets: 4 },
	{ id: 'b-alerts', name: 'Alerts', description: 'Tickets opened by alert policies.', position: 1, statuses: boardStatuses('b-alerts'), open_tickets: 1 }
];
const ticketTypes = ['Incident', 'Service request', 'Problem', 'Change', 'Alert'].map((name, position) => ({ id: `tt-${position}`, name, position }));
const contacts = [
	{ id: 'ct-ann', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-hq', site_name: 'Head office', name: 'Ann Lopez', email: 'ann@acme.example', phone: '+1 555 0101', job_title: 'Office manager', notes: '', is_primary: true, portal_enabled: false, open_tickets: 2, created_at: ago(60 * 24 * 100), updated_at: ago(60 * 24 * 100) },
	{ id: 'ct-raj', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-wh', site_name: 'Warehouse', name: 'Raj Patel', email: 'raj@acme.example', phone: '', job_title: 'Warehouse lead', notes: '', is_primary: false, portal_enabled: false, open_tickets: 0, created_at: ago(60 * 24 * 60), updated_at: ago(60 * 24 * 60) }
];
/** Scheduled reports (`/report-schedules`). */
const reportSchedule = (id: string, name: string, report: string, client: string | null, cron: string, range: string, extra: Record<string, unknown> = {}) => ({
	id, name, report, client_id: client, client_name: clients.find((c) => c.id === client)?.name ?? null, params: { range }, cron, timezone: 'Europe/London',
	user_ids: ['u-1'], contact_ids: [], extra_emails: [], subject: '', message: '', enabled: true, owner_id: 'u-1', owner_name: 'Dana Admin',
	next_run_at: new Date(Date.UTC(2026, 6, 1, 6, 0)).toISOString(), last_run_at: ago(60 * 24 * 23), last_status: 'sent', last_error: null,
	created_at: ago(60 * 24 * 90), updated_at: ago(60 * 24 * 30), ...extra
});
const reportSchedules = [
	reportSchedule('rs-qbr', 'Acme quarterly review', 'qbr', 'c-acme', '0 7 1 1,4,7,10 *', 'last_quarter', { contact_ids: ['ct-ann'], message: 'Your review for last quarter is attached.' }),
	reportSchedule('rs-desk', 'Service desk, weekly', 'service_desk', null, '0 7 * * 1', 'last_week', { user_ids: ['u-1', 'u-2'], next_run_at: new Date(Date.UTC(2026, 5, 22, 6, 0)).toISOString(), last_run_at: ago(60 * 24 * 2) }),
	reportSchedule('rs-profit', 'Margins for the partners', 'profitability', null, '0 7 1 * *', 'last_month', {
		owner_id: 'u-2', owner_name: 'Terry Tech', last_status: 'failed', last_error: 'the owner lacks the billing.read permission', extra_emails: ['partners@northwind.example']
	}),
	reportSchedule('rs-off', 'Utilisation (paused)', 'utilisation', null, '0 7 1 * *', 'last_month', { enabled: false, next_run_at: null, last_run_at: null, last_status: null })
];
const reportRuns = [
	{ id: 'rr-2', schedule_id: 'rs-qbr', trigger: 'manual', started_at: ago(60 * 3), finished_at: ago(60 * 3), status: 'sent', from_date: '2026-01-01', to_date: '2026-03-31', bytes: 48_211,
	  recipients: [{ kind: 'user', id: 'u-1', email: 'dana@northwind.example', status: 'queued' }, { kind: 'contact', id: 'ct-ann', email: 'ann@acme.example', status: 'queued' }], error: null, started_by_name: 'Dana Admin', stored: true },
	{ id: 'rr-1', schedule_id: 'rs-qbr', trigger: 'schedule', started_at: ago(60 * 24 * 85), finished_at: ago(60 * 24 * 85), status: 'sent', from_date: '2026-01-01', to_date: '2026-03-31', bytes: 47_002,
	  recipients: [{ kind: 'user', id: 'u-1', email: 'dana@northwind.example', status: 'queued' }, { kind: 'contact', id: 'ct-old', email: '', status: 'skipped', reason: 'the contact was deleted' }], error: null, started_by_name: null, stored: true }
];

type T = Record<string, unknown> & { id: string; client_id: string | null };
function ticket(i: number, subject: string, clientId: string | null, cat: string, prio: number, extra: Partial<T> = {}): T {
	const c = clients.find((x) => x.id === clientId);
	const board = extra.board_id === 'b-alerts' ? boards[1] : boards[0];
	const st = board.statuses.find((s) => s.category === cat)!;
	return {
		id: `t-${i}`, number: 10400 + i, subject, client_id: clientId, client_name: c?.name ?? null, site_id: null, site_name: null, contact_id: null, contact_name: null,
		contact_email: null, board_id: board.id, board_name: board.name, status_id: st.id, status_name: st.name, status_category: cat, type_id: null, type_name: null,
		priority: prio, impact: null, urgency: null, source: 'email', assignee_id: null, assignee_name: null, requester_name: '', requester_email: '',
		created_at: ago(60 * 5 * i), updated_at: ago(17 * i), first_response_at: null, resolved_at: null, closed_at: null, merged_into: null, merged_into_number: null,
		alert_policy_id: null, alert_reopens: 0, agent_count: 0, ...extra
	};
}
const tickets: T[] = [
	ticket(1, 'Printer on the second floor prints blank pages', 'c-acme', 'open', 2, { contact_id: 'ct-ann', contact_name: 'Ann Lopez', contact_email: 'ann@acme.example', assignee_id: 'u-1', assignee_name: 'Dana Admin', agent_count: 1, first_response_at: ago(200), type_id: 'tt-0', type_name: 'Incident', impact: 2, urgency: 1 }),
	ticket(2, 'Disk at or above 95% on acme-fs01', 'c-acme', 'new', 1, { board_id: 'b-alerts', source: 'alert', alert_policy_id: 'p-disk', agent_count: 1, type_id: 'tt-4', type_name: 'Alert' }),
	ticket(3, 'New starter on Monday: laptop and accounts', 'c-globex', 'waiting_client', 3, { source: 'dashboard', assignee_id: 'u-2', assignee_name: 'Terry Tech', requester_name: 'Gil Bates', requester_email: 'gil@globex.example' }),
	ticket(4, 'VPN disconnects every hour', null, 'new', 3, { requester_name: 'Sam Doe', requester_email: 'sam@unknown.example' }),
	ticket(5, 'Renew the SSL certificate for the intranet', 'c-initech', 'open', 4, { source: 'dashboard' }),
	ticket(6, 'Outlook keeps asking for a password', 'c-acme', 'resolved', 3, { contact_id: 'ct-raj', contact_name: 'Raj Patel', resolved_at: ago(60 * 20) })
];
const ticketDocs: Record<string, string[]> = { 't-1': ['d-printer', 'd-network'], 't-6': ['d-network'] };
function ticketDetail(t: T) {
	const a = agents.find((x) => x.id === (t.id === 't-2' ? 'a-2' : 'a-3'))!;
	const ev = (id: number, kind: string, mins: number, extra: Record<string, unknown>) => ({
		id, kind, public: false, author_id: null, author_contact_id: null, author_kind: 'system', author_name: 'System', body: '', data: {}, created_at: ago(mins),
		email_status: null, email_error: null, email_to: null, ...extra
	});
	const events = t.id === 't-1'
		? [
				ev(1, 'created', 300, { public: true, author_contact_id: 'ct-ann', author_kind: 'contact', author_name: 'Ann Lopez', body: 'Since this morning the printer next to the kitchen prints blank pages. Tried turning it off and on.', data: { source: 'email' } }),
				ev(2, 'change', 280, { author_id: 'u-1', author_kind: 'user', author_name: 'Dana Admin', data: { field: 'assignee', from: null, to: 'Dana Admin' } }),
				ev(3, 'job', 250, { author_id: 'u-1', author_kind: 'user', author_name: 'Dana Admin', data: { job_id: 'j-1', hostname: a.hostname, script: 'Restart print spooler', status: 'started' } }),
				ev(4, 'job', 249, { author_name: a.hostname, body: 'Stopping Print Spooler...\nStarting Print Spooler...\nThe Print Spooler service was started successfully.', data: { job_id: 'j-1', hostname: a.hostname, script: 'Restart print spooler', status: 'succeeded', exit_code: 0 } }),
				ev(5, 'note', 230, { author_id: 'u-1', author_kind: 'user', author_name: 'Dana Admin', body: 'Spooler restart didn’t help. Toner drum looks worn; ordering a replacement.' }),
				ev(6, 'reply', 200, { public: true, author_id: 'u-1', author_kind: 'user', author_name: 'Dana Admin', body: 'Hi Ann, a new drum is on its way and should arrive tomorrow. Meanwhile please use the printer in reception.', email_status: 'sent', email_to: ['ann@acme.example'] }),
				ev(7, 'change', 199, { author_id: 'u-1', author_kind: 'user', author_name: 'Dana Admin', data: { field: 'status', from: 'New', to: 'In progress' } }),
				ev(9, 'doc', 190, { author_id: 'u-1', author_kind: 'user', author_name: 'Dana Admin', data: { doc_id: 'd-printer', title: 'Second-floor printer quirks', linked: true } }),
				ev(8, 'message', 45, { public: true, author_contact_id: 'ct-ann', author_kind: 'contact', author_name: 'Ann Lopez', body: 'Thanks, will do!', data: { from: 'ann@acme.example' } })
			]
		: [ev(1, 'created', 60, { author_name: 'Alert', body: `${t.subject}\nSeverity: critical` }), ev(2, 'alert', 60, { author_name: 'Alert', data: { alert_id: 'al-1', state: 'opened' } })];
	return {
		...t, events, attachments: t.id === 't-1' ? [{ id: 'at-1', event_id: 1, name: 'test-page.pdf', content_type: 'application/pdf', size: 182_400, uploaded_by_name: null, created_at: ago(300) }] : [],
		agents: [{ ...a, capabilities: ['patch', 'desktop'], reboot_pending: false, missing_patches: 3, alerts: alerts.filter((x) => x.agent_id === a.id && x.state !== 'resolved').slice(0, 3).map((x) => ({ id: x.id, title: x.title, severity: x.severity, opened_at: x.opened_at })) }],
		// Pages linked to the ticket, by title (clientDocs is defined further down).
		docs: (ticketDocs[t.id] ?? []).map((id) => clientDocs.find((d) => d.id === id)!).sort((x, y) => x.title.localeCompare(y.title))
			.map((d) => ({ id: d.id, title: d.title, category: d.category, updated_at: d.updated_at, updated_by_name: d.updated_by_name })),
		statuses: boards.find((b) => b.id === t.board_id)!.statuses, reply_to: (t.contact_email as string) || (t.requester_email as string) || null
	};
}
const mailboxes = [
	{ id: 'mb-1', name: 'Support', address: 'support@northwind.example', kind: 'imap', imap_host: 'imap.fastmail.com', imap_port: 993, imap_security: 'tls', imap_username: 'support@northwind.example', has_password: true, imap_folder: 'INBOX', board_id: 'b-desk', board_name: 'Service Desk', auto_reply: true, enabled: true, last_polled_at: ago(1), last_error: null, received_24h: 14, created_at: ago(60 * 24 * 30) },
	{ id: 'mb-2', name: 'Escalations', address: 'urgent@northwind.example', kind: 'webhook', imap_host: '', imap_port: 993, imap_security: 'tls', imap_username: '', has_password: false, imap_folder: 'INBOX', board_id: 'b-desk', board_name: 'Service Desk', auto_reply: false, enabled: true, last_polled_at: null, last_error: null, received_24h: 1, created_at: ago(60 * 24 * 10) }
];
const inboundMail = [
	{ id: 'e1', mailbox_name: 'Support', from_addr: 'ann@acme.example', subject: 'Re: Printer on the second floor prints blank pages [T-10401]', status: 'received', ignored_reason: null, ticket_id: 't-1', ticket_number: 10401, created_at: ago(45) },
	{ id: 'e2', mailbox_name: 'Support', from_addr: 'noreply@vendor.example', subject: 'Your weekly newsletter', status: 'ignored', ignored_reason: 'bulk or list mail', ticket_id: null, ticket_number: null, created_at: ago(120) },
	{ id: 'e3', mailbox_name: 'Support', from_addr: 'sam@unknown.example', subject: 'VPN disconnects every hour', status: 'received', ignored_reason: null, ticket_id: 't-4', ticket_number: 10404, created_at: ago(20 * 4) }
];
function ticketList(q: URLSearchParams) {
	const view = q.get('view') ?? 'open';
	const done = (t: T) => t.status_category === 'resolved' || t.status_category === 'closed';
	return tickets.filter(
		(t) =>
			(view === 'all' || (view === 'done' ? done(t) : view === 'triage' ? !t.client_id && !done(t) : view === 'mine' ? t.assignee_id === 'u-1' && !done(t) : view === 'unassigned' ? !t.assignee_id && !done(t) : view === 'waiting' ? String(t.status_category).startsWith('waiting') : !done(t))) &&
			(!q.get('client_id') || t.client_id === q.get('client_id')) && (!q.get('agent_id') || t.agent_count)
	);
}

// --- security ---------------------------------------------------------------------------------
type Prod = Record<string, unknown> & { kind: string; name: string; enabled: boolean | null; realtime: boolean | null };
const defender = (sigMins: number, extra: Partial<Prod> = {}): Prod => ({
	kind: 'defender', name: 'Microsoft Defender Antivirus', version: '4.18.25090.3009', enabled: true, realtime: true,
	signature_version: '1.439.218.0', signatures_updated_at: ago(sigMins), signatures_current: null, last_quick_scan_at: ago(60 * 20),
	last_full_scan_at: ago(60 * 24 * 10), tamper_protection: true, actions: ['quick_scan', 'full_scan', 'update_signatures'], detail: 'Engine 1.1.25090.3001', ...extra
});
const clamav = (sigMins: number, extra: Partial<Prod> = {}): Prod => ({
	kind: 'clamav', name: 'ClamAV', version: '1.4.3', enabled: true, realtime: false, signature_version: '27671', signatures_updated_at: ago(sigMins),
	signatures_current: null, last_quick_scan_at: ago(60 * 24 * 2), last_full_scan_at: null, tamper_protection: null,
	actions: ['quick_scan', 'full_scan', 'update_signatures'], detail: 'Scans load the signatures themselves (clamd isn\'t running)', ...extra
});
const security: Record<string, { state: string; products: Prod[]; reported: number | null }> = {
	'a-1': { state: 'protected', products: [defender(180)], reported: 4 },
	'a-2': { state: 'threats', products: [defender(95)], reported: 2 },
	'a-3': { state: 'at_risk', products: [clamav(60 * 20)], reported: 3 },
	'a-4': {
		state: 'protected',
		products: [
			{ kind: 'other', name: 'Sophos Intercept X', version: null, enabled: true, realtime: true, signature_version: null, signatures_updated_at: null, signatures_current: true, last_quick_scan_at: null, last_full_scan_at: null, tamper_protection: null, actions: [], detail: 'Reported by Windows Security Center' },
			defender(60 * 30, { enabled: false, realtime: false, detail: 'Passive Mode (another antivirus is primary)', last_quick_scan_at: null })
		],
		reported: 40
	},
	'a-5': { state: 'unprotected', products: [], reported: 6 },
	'a-6': { state: 'at_risk', products: [clamav(60 * 24 * 6)], reported: 5 },
	'a-7': { state: 'unknown', products: [], reported: null }
};
const detections = [
	{ id: 'd-1', agent_id: 'a-2', product: 'defender', name: 'Trojan:Win32/Wacatac.B!ml', severity: 'severe', status: 'active', resources: ['file:_C:\\Users\\jsmith\\Downloads\\invoice_0614.pdf.exe', 'process:_pid:4412'], process: 'C:\\Windows\\explorer.exe', username: 'ACME\\jsmith', detected_at: ago(25), first_seen_at: ago(24), last_seen_at: ago(2), resolved_at: null },
	{ id: 'd-2', agent_id: 'a-2', product: 'defender', name: 'PUA:Win32/Presenoker', severity: 'low', status: 'quarantined', resources: ['file:_C:\\Users\\jsmith\\AppData\\Local\\Temp\\setup_x64.exe'], process: null, username: 'ACME\\jsmith', detected_at: ago(60 * 26), first_seen_at: ago(60 * 26), last_seen_at: ago(2), resolved_at: ago(60 * 26) },
	{ id: 'd-3', agent_id: 'a-1', product: 'defender', name: 'Virus:DOS/EICAR_Test_File', severity: 'severe', status: 'removed', resources: ['file:_C:\\temp\\eicar.com'], process: null, username: 'ACME\\dana', detected_at: ago(60 * 24 * 2), first_seen_at: ago(60 * 24 * 2), last_seen_at: ago(4), resolved_at: ago(60 * 24 * 2) },
	{ id: 'd-4', agent_id: 'a-3', product: 'clamav', name: 'Unix.Trojan.Mirai-7100807-0', severity: 'unknown', status: 'removed', resources: ['/tmp/.x/bins.sh'], process: null, username: null, detected_at: ago(60 * 24 * 2), first_seen_at: ago(60 * 24 * 2), last_seen_at: ago(3), resolved_at: ago(60 * 24 * 1) }
].map((d) => {
	const a = agents.find((x) => x.id === d.agent_id)!;
	return { ...d, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name, site_name: a.site_name };
});
const securityActions: Record<string, Record<string, unknown>[]> = {
	'a-2': [
		{ id: 'sa-3', product: 'defender', action: 'quick_scan', status: 'running', message: null, created_by_name: 'Dana Admin', created_at: ago(3), started_at: ago(3), finished_at: null },
		{ id: 'sa-2', product: 'defender', action: 'update_signatures', status: 'succeeded', message: 'Signatures updated', created_by_name: 'Dana Admin', created_at: ago(95), started_at: ago(95), finished_at: ago(94) }
	],
	'a-3': [
		{ id: 'sa-1', product: 'clamav', action: 'quick_scan', status: 'succeeded', message: 'Found 1 infected file (18,204 files scanned)', created_by_name: 'Terry Tech', created_at: ago(60 * 24 * 2 + 9), started_at: ago(60 * 24 * 2 + 9), finished_at: ago(60 * 24 * 2) },
		{ id: 'sa-0', product: 'clamav', action: 'update_signatures', status: 'failed', message: 'freshclam failed: Can\'t connect to port 80 of host database.clamav.net', created_by_name: 'Terry Tech', created_at: ago(60 * 24 * 3), started_at: ago(60 * 24 * 3), finished_at: ago(60 * 24 * 3 - 1) }
	]
};
function securityRow(a: Agent) {
	const s = security[a.id];
	const enabled = s.products.filter((p) => p.enabled);
	const sigs = enabled.map((p) => p.signatures_updated_at as string | null).filter(Boolean).sort().reverse();
	const scans = s.products.flatMap((p) => [p.last_quick_scan_at, p.last_full_scan_at] as (string | null)[]).filter(Boolean).sort().reverse();
	return {
		id: a.id, hostname: a.hostname, online: a.online, os_family: a.os_family, client_id: a.client_id, client_name: a.client_name, site_id: a.site_id, site_name: a.site_name,
		state: s.state, security_at: s.reported === null ? null : ago(s.reported), security_error: null,
		products: s.products.map(({ kind, name, enabled, realtime }) => ({ kind, name, enabled, realtime })),
		signatures_updated_at: sigs[0] ?? null, last_scan_at: scans[0] ?? null,
		active_threats: allDetections.filter((d) => d.agent_id === a.id && d.status === 'active' && !d.resolved_at && !d.audit).length,
		running_action: a.id === 'a-2' ? 'quick_scan' : null,
		isolated: sensors[a.id].isolated, sensor: sensors[a.id].sensor, content_version: (sensors[a.id].sensor?.content_version as string | null) ?? null,
		risks: risks[a.id] ?? [], database_version: agentDb(a.id)?.version ?? null, database_built_at: agentDb(a.id)?.built_at ?? null, database_max_age_hours: 72,
		prevention: !!sensors[a.id].policy.prevention
	};
}
function securitySummary(client: string | null) {
	const rows = agents.filter((a) => !client || a.client_id === client).map(securityRow);
	const by = Object.fromEntries(['threats', 'unprotected', 'at_risk', 'unknown', 'protected'].map((k) => [k, rows.filter((r) => r.state === k).length]));
	return { agents: by, active_threats: rows.reduce((n, r) => n + r.active_threats, 0), detections_7d: 3, actions_running: 1 };
}

// --- security: our sensor, response, investigation (Phase 8, milestones 2-7) -------------------
const HASH_BEACON = '9f2c4e1a7b3d5f60812a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d';
const HASH_DROPPER = '3b7a91c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8';
const HASH_MINER = 'e8a3c1f0b9d7e5c3a1f9e7d5c3b1a9f8e6d4c2b0a8f6e4d2c0b8a6f4e2d0c8b6';
const sensorPolicy = (o: Record<string, unknown> = {}) => ({
	enabled: true, quick_scan_hours: 24, full_scan_days: 7, auto_quarantine: true, prevention: true, telemetry_mb: 256, canaries: true,
	exclusions: [{ kind: 'path', value: 'D:\\Backups\\' }], rule_modes: [], realtime: 'block', scan_on_write: true, archive_depth: 5, reputation: true, ...o
});
const DB_GENERAL = '2026.06.14.2';
const DB_OLD = '2026.06.10.1';
/** Real-time protection as the sensor reports it. */
const realtime = (o: Record<string, unknown> = {}) => ({
	mode: 'block', state: 'unavailable', mechanism: 'scan-after-start', error: 'on-access protection is Linux only; programs are scanned after they start', scan_on_write: true,
	filesystems: 0, decisions: 0, denied: 0, cache_hits: 0, timeouts: 0, overloaded: 0, write_scans: 0, write_dropped: 0, p50_us: 0, p99_us: 0, ...o
});
const health = (o: Record<string, unknown> = {}) => ({
	events_total: 1_284_330, events_per_min: 212.4, store_bytes: 141 * 2 ** 20, cpu_percent: 0.8, rss_bytes: 38 * 2 ** 20, rules: 64,
	collectors: [['process', 'etw'], ['network', 'etw'], ['file', 'etw'], ['registry', 'etw'], ['realtime', 'scan-after-start']], canaries: 6, last_scan: ago(60 * 5),
	database_version: DB_GENERAL, yara_rules: 3_015, hash_signatures: 1_046_210, files_scanned: 48_211, cache_hits: 391_877, realtime: realtime(), ...o
});
const linuxCollectors = [['process', 'proc-connector'], ['network', 'poll'], ['file', 'fanotify']];
const sensors: Record<string, { sensor: Record<string, unknown> | null; policy: Record<string, unknown>; isolated: boolean }> = {
	'a-1': { sensor: { enabled: true, running: true, restarts: 4, content_version: '2026.06.14.1', error: null, isolated: false, health: health({ events_per_min: 96.1, cpu_percent: 1.4 }) }, policy: sensorPolicy(), isolated: false },
	'a-2': { sensor: { enabled: true, running: true, restarts: 0, content_version: '2026.06.14.1', error: null, isolated: true, health: health() }, policy: sensorPolicy(), isolated: true },
	'a-3': {
		sensor: {
			enabled: true, running: true, restarts: 2, content_version: '2026.06.10.2', error: null, isolated: false, database_version: DB_GENERAL,
			health: health({ events_per_min: 58.2, collectors: [...linuxCollectors, ['realtime', 'scan-after-start']], canaries: 0, files_scanned: 9_120, cache_hits: 61_004, realtime: realtime({ error: 'fanotify_init: Operation not permitted (the agent needs CAP_SYS_ADMIN; is it in a container?)' }) })
		},
		policy: sensorPolicy({ canaries: false }), isolated: false
	},
	'a-4': { sensor: { enabled: true, running: false, restarts: 1, content_version: '2026.06.10.2', error: 'the sensor exited (status 137); restarting in 30 s', isolated: false, health: null }, policy: sensorPolicy({ prevention: false }), isolated: false },
	'a-5': { sensor: { enabled: false, running: false, restarts: 0, content_version: null, error: null, isolated: false, health: null }, policy: sensorPolicy({ enabled: false }), isolated: false },
	'a-6': {
		sensor: {
			enabled: true, running: true, restarts: 0, content_version: '2026.06.14.1', error: `signature database ${DB_GENERAL}: download failed: connection reset by peer (retrying in 10 min)`, isolated: false, database_version: DB_OLD,
			health: health({
				collectors: [...linuxCollectors, ['realtime', 'fanotify']], canaries: 0, database_version: DB_OLD, hash_signatures: 980_112, yara_rules: 2_870, files_scanned: 21_402, cache_hits: 188_950,
				realtime: realtime({ state: 'on', mechanism: 'fanotify', error: null, filesystems: 3, decisions: 18_204, denied: 1, cache_hits: 17_311, timeouts: 2, write_scans: 52_117, p50_us: 14, p99_us: 3_600 })
			})
		},
		policy: sensorPolicy({ canaries: false }), isolated: false
	},
	'a-7': { sensor: null, policy: sensorPolicy(), isolated: false }
};
const rmmProduct = (a: string, o: Partial<Prod> = {}): Prod => ({
	kind: 'rmm', name: 'RMM sensor', version: '0.4.2', enabled: true, realtime: false, signature_version: DB_GENERAL, signatures_updated_at: ago(60 * 22),
	signatures_current: null, last_quick_scan_at: ago(60 * 5), last_full_scan_at: ago(60 * 24 * 3), tamper_protection: null, actions: ['quick_scan', 'full_scan'], detail: a === 'a-1' ? 'Engine 0.4.2' : null, ...o
});
security['a-1'].products.push(rmmProduct('a-1'));
security['a-2'].products.push(rmmProduct('a-2'));
security['a-3'].products.push(rmmProduct('a-3'));
security['a-6'].products.push(rmmProduct('a-6', { realtime: true, signature_version: DB_OLD, signatures_updated_at: ago(60 * 24 * 5) }));
/** Why each agent is at risk (the server's `risks`). */
const risks: Record<string, string[]> = { 'a-3': ['realtime_off', 'sensor_realtime'], 'a-6': ['signatures', 'database'] };
const dbBuilt: Record<string, string> = { [DB_GENERAL]: ago(60 * 22), [DB_OLD]: ago(60 * 24 * 5) };
function agentDb(a: string) {
	const z = sensors[a].sensor as { database_version?: string; health?: { database_version?: string } | null } | null;
	const v = z?.database_version ?? z?.health?.database_version;
	if (!v) return null;
	const general = v === DB_GENERAL;
	return { version: v, built_at: dbBuilt[v], stage: general ? 'general' : 'retired', hashes: general ? 1_046_210 : 980_112, yara_rules: general ? 3_015 : 2_870, size: general ? 39_604_224 : 37_311_488 };
}
const proc = (pid: number, ppid: number, name: string, exe: string, cmd: string, started: number, user = 'ACME\\jsmith', sha256?: string) => ({ pid, ppid, name, exe, command_line: cmd, user, sha256, started_at: ago(started) });
const pExplorer = proc(3120, 2988, 'explorer.exe', 'C:\\Windows\\explorer.exe', 'C:\\Windows\\Explorer.EXE', 60 * 6);
const pWord = proc(5544, 3120, 'WINWORD.EXE', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\jsmith\\Downloads\\Invoice_0614.docm"', 28);
const pPs = proc(6120, 5544, 'powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA', 27, 'ACME\\jsmith', 'de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c');
const ev = (seq: number, mins: number, kind: string, action: string, extra: Record<string, unknown>) => ({ seq, ts: ago(mins), kind, action, ...extra });
const contextD5 = [
	ev(88412, 27, 'process', 'start', { process: pPs, parent: pWord }),
	ev(88100, 28, 'process', 'running', { process: pWord }),
	ev(10220, 60 * 6, 'process', 'running', { process: pExplorer }),
	ev(88415, 26.9, 'network', 'connect', { process: pPs, network: { protocol: 'tcp', local_addr: '10.1.0.24', local_port: 51544, remote_addr: '185.220.101.4', remote_port: 443 } }),
	ev(88419, 26.8, 'file', 'create', { process: pPs, file: { path: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd4412.exe', sha256: HASH_BEACON } }),
	ev(88422, 26.7, 'registry', 'set', { process: pPs, registry: { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'OneDriveSync', data: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd4412.exe' } }),
	ev(88430, 26.5, 'process', 'start', { process: proc(7012, 6120, 'upd4412.exe', 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd4412.exe', 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd4412.exe', 26.5, 'ACME\\jsmith', HASH_BEACON), parent: pPs })
];
const extraDetections = [
	{ id: 'd-5', agent_id: 'a-2', product: 'rmm', source: 'behaviour', name: 'Office application started an encoded PowerShell command', severity: 'high', status: 'active', resources: ['process:_pid:6120'], process: pPs.exe, username: 'ACME\\jsmith', detected_at: ago(27), first_seen_at: ago(27), last_seen_at: ago(27), resolved_at: null, rule_id: 'RMM-B-0007', mitre: ['T1059.001', 'T1566.001'], audit: false, action_taken: null, sha256: null, verdict: null },
	{ id: 'd-6', agent_id: 'a-2', product: 'rmm', source: 'file', name: 'Known-bad file: Cobalt Strike beacon', severity: 'severe', status: 'quarantined', resources: ['file:_C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd4412.exe'], process: null, username: 'ACME\\jsmith', detected_at: ago(26), first_seen_at: ago(26), last_seen_at: ago(26), resolved_at: ago(26), rule_id: 'RMM-F-0002', mitre: ['T1071.001'], audit: false, action_taken: 'Quarantined automatically', sha256: HASH_BEACON, verdict: 'true_positive' },
	{ id: 'd-7', agent_id: 'a-1', product: 'rmm', source: 'behaviour', name: 'Scheduled task created from a temp folder', severity: 'moderate', status: 'active', resources: [], process: 'C:\\Windows\\System32\\schtasks.exe', username: 'ACME\\dana', detected_at: ago(60 * 9), first_seen_at: ago(60 * 9), last_seen_at: ago(60 * 9), resolved_at: null, rule_id: 'RMM-B-0031', mitre: ['T1053.005'], audit: true, action_taken: null, sha256: null, verdict: 'benign' },
	{ id: 'd-8', agent_id: 'a-6', product: 'rmm', source: 'file', name: 'CoinMiner.XMRig', severity: 'high', status: 'quarantined', resources: ['/var/tmp/.cache/kswapd0'], process: '/var/tmp/.cache/kswapd0 --donate-level 1 -o pool.example:443', username: 'postgres', detected_at: ago(50), first_seen_at: ago(50), last_seen_at: ago(50), resolved_at: ago(50), rule_id: 'RMM-HASH', mitre: ['T1496'], audit: false, action_taken: 'denied before it ran, quarantined', sha256: HASH_MINER, verdict: null, found_by: 'on_exec', denied: true }
].map((d) => {
	const a = agents.find((x) => x.id === d.agent_id)!;
	return { ...d, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name, site_name: a.site_name };
});
const allDetections = [
	...extraDetections.slice(0, 2).map((d) => ({ ...d, found_by: d.source === 'file' ? 'scan' : null, denied: false })),
	extraDetections[3],
	...detections.map((d) => ({ ...d, source: 'product', rule_id: null, mitre: [] as string[], audit: false, action_taken: d.status === 'active' ? null : d.status === 'quarantined' ? 'Quarantined' : 'Removed', sha256: d.id === 'd-3' ? '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' : null, verdict: d.id === 'd-3' ? 'benign' : null, found_by: null, denied: false })),
	{ ...extraDetections[2], found_by: null, denied: false }
].sort((x, y) => Date.parse(y.detected_at) - Date.parse(x.detected_at));
const quarantine = [
	{ id: 'q-1', agent_id: 'a-2', path: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd4412.exe', sha256: HASH_BEACON, size: 284_672, reason: 'Known-bad file: Cobalt Strike beacon (RMM-F-0002)', quarantined_at: ago(26), state: 'quarantined', updated_at: ago(26) },
	{ id: 'q-2', agent_id: 'a-2', path: 'C:\\Users\\jsmith\\Downloads\\Invoice_0614.docm', sha256: HASH_DROPPER, size: 61_440, reason: 'Quarantined by Dana Admin', quarantined_at: ago(20), state: 'quarantined', updated_at: ago(20) },
	{ id: 'q-3', agent_id: 'a-6', path: '/tmp/.cache/kdevtmpfsi', sha256: 'c41f9a0e7d2b5c8f3e6a1d4b7c0f2e5a8d1b4c7e0f3a6d9b2c5e8f1a4d7b0c3e', size: 2_301_440, reason: 'Linux coin miner (RMM-F-0011)', quarantined_at: ago(60 * 24 * 4), state: 'deleted', updated_at: ago(60 * 24 * 3) },
	{ id: 'q-4', agent_id: 'a-1', path: 'C:\\Tools\\nirsoft\\WebBrowserPassView.exe', sha256: '7e3d1c9b5a7f2e4d6c8b0a1f3e5d7c9b2a4f6e8d0c1b3a5f7e9d2c4b6a8f0e1d', size: 412_160, reason: 'Password recovery tool (RMM-F-0020)', quarantined_at: ago(60 * 24 * 6), state: 'restored', updated_at: ago(60 * 24 * 5) }
].map((q) => {
	const a = agents.find((x) => x.id === q.agent_id)!;
	return { ...q, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name };
});
const act = (id: string, action: string, status: string, mins: number, o: Record<string, unknown> = {}) => ({
	id, product: 'rmm', action, status, message: null, created_by_name: 'Dana Admin', created_at: ago(mins), started_at: ago(mins), finished_at: status === 'running' || status === 'sent' ? null : ago(mins - 1),
	params: {}, result: null, has_download: false, ...o
});
securityActions['a-2'] = [
	{ ...securityActions['a-2'][0], params: {}, result: null, has_download: false },
	act('sa-9', 'isolate', 'succeeded', 18, { params: { type: 'isolate', allow: [] }, message: 'Network isolated' }),
	act('sa-8', 'quarantine_file', 'succeeded', 20, { params: { type: 'quarantine_file', path: 'C:\\Users\\jsmith\\Downloads\\Invoice_0614.docm' }, message: 'Quarantined (61 KB)' }),
	act('sa-7', 'kill_process', 'succeeded', 22, { params: { type: 'kill_process', pid: 6120, tree: true }, message: 'Killed 2 processes' }),
	act('sa-6', 'collect_triage', 'succeeded', 21, { params: { type: 'collect_triage' }, message: 'Triage package ready (4.2 MB)', has_download: true }),
	{ ...securityActions['a-2'][1], params: {}, result: null, has_download: false }
];
securityActions['a-1'] = [
	act('sa-12', 'scan_path', 'failed', 40, { params: { type: 'scan_path', path: 'E:\\Shares\\Finance' }, message: 'path not found' }),
	act('sa-11', 'collect_triage', 'succeeded', 60 * 9, { params: { type: 'collect_triage' }, message: 'Triage package ready (3.8 MB)', has_download: true, created_by_name: 'Terry Tech' }),
	act('sa-10', 'quick_scan', 'succeeded', 60 * 5, { message: 'Scanned 48,211 files, nothing found', created_by_name: null })
];
securityActions['a-3'] = (securityActions['a-3'] ?? []).map((a) => ({ ...a, params: {}, result: null, has_download: false }));
function agentSecurity(a: Agent) {
	const s = security[a.id];
	const z = sensors[a.id];
	return {
		supported: a.id !== 'a-7', online: a.online, state: s.state, reported_at: s.reported === null ? null : ago(s.reported), error: null, products: s.products,
		detections: allDetections.filter((d) => d.agent_id === a.id), actions: securityActions[a.id] ?? [],
		sensor_supported: a.id !== 'a-7', sensor: z.sensor, sensor_at: z.sensor ? ago(1) : null, content_version: (z.sensor?.content_version as string | null) ?? null,
		isolated: z.isolated, policy: z.policy, quarantine: quarantine.filter((q) => q.agent_id === a.id && q.state === 'quarantined'),
		risks: risks[a.id] ?? [], database: agentDb(a.id), database_max_age_hours: 72
	};
}
const minerPrevalence = [
	{ agent_id: 'a-5', hostname: 'globex-app01', client_name: 'Globex', first_seen: ago(60 * 24 * 2 + 40), how: 'ran', path: '/tmp/.X11-unix/.k/kswapd0' },
	{ agent_id: 'a-6', hostname: 'globex-db01', client_name: 'Globex', first_seen: ago(50), how: 'detected, quarantined', path: '/var/tmp/.cache/kswapd0' }
];
const minerReputation = [
	{ name: 'CoinMiner.XMRig', severity: 'high', source: `db:${DB_OLD}`, added_at: ago(60 * 24 * 5) },
	{ name: 'xmrig', severity: 'high', source: 'list:malwarebazaar-full', added_at: ago(60 * 24 * 2) }
];
function detectionDetail(id: string) {
	const d = allDetections.find((x) => x.id === id)!;
	const a = agents.find((x) => x.id === d.agent_id)!;
	const isD5 = d.id === 'd-5';
	return {
		...d, os_family: a.os_family, online: a.online, isolated: sensors[a.id].isolated, context: isD5 ? contextD5 : [], context_unavailable: false,
		content_version: d.product === 'rmm' ? '2026.06.14.1' : null, notes: d.verdict ? 'Confirmed with the user: opened an invoice from an unknown sender.' : null,
		verdict_by_name: d.verdict ? 'Dana Admin' : null, verdict_at: d.verdict ? ago(15) : null, quarantine_id: d.id === 'd-6' ? 'q-1' : null,
		prevalence: d.sha256 === HASH_BEACON || isD5 ? [{ agent_id: 'a-4', hostname: 'acme-pos-07', client_name: 'Acme Corp', first_seen: ago(60 * 3), how: 'Quarantined (RMM-F-0002)' }] : d.id === 'd-8' ? minerPrevalence : [],
		...(d.sha256 === HASH_BEACON ? { seen_on: 2, first_seen: ago(60 * 3), reputation: [] } : d.id === 'd-8' ? { seen_on: 2, first_seen: ago(60 * 24 * 2 + 40), reputation: minerReputation } : d.sha256 ? { seen_on: 1, first_seen: d.first_seen_at, reputation: [] } : {}),
		database_version: d.product === 'rmm' && d.source === 'file' ? (d.id === 'd-8' ? DB_OLD : DB_GENERAL) : null, part: null,
		actions: isD5 ? securityActions['a-2'].filter((x) => ['sa-6', 'sa-7', 'sa-9'].includes(x.id as string)) : [],
		alert: isD5 ? { id: 'al-5', title: 'Threat: Office application started an encoded PowerShell command', state: 'open' } : null,
		rule: isD5 ? { id: 'RMM-B-0007', name: 'Office spawns encoded PowerShell', description: 'A Microsoft Office application started PowerShell with an encoded command, the usual first step of a malicious macro.', kind: 'behaviour', event: 'process', severity: 'high', confidence: 'high', mode: 'alert', mitre: ['T1059.001', 'T1566.001'], digest: 'c0ffee' } : null
	};
}
const rule = (id: string, name: string, kind: 'file' | 'behaviour', event: string | null, severity: string, confidence: string, mode: string, mitre: string[], o: Record<string, unknown> = {}) => ({
	id, name, description: '', kind, event, severity, confidence, mode, mitre, digest: null, override_mode: null, override_reason: null, effective_mode: mode,
	first_seen: ago(60 * 24 * 40), stage: 'general', hits_7d: 0, audit_hits_7d: 0, agents_30d: 0, true_positives: 0, false_positives: 0, fp_rate: null, can_block: false,
	block_blocker: 'only high-confidence rules can block', ...o
});
const rules = [
	rule('RMM-B-0007', 'Office spawns encoded PowerShell', 'behaviour', 'process', 'high', 'high', 'alert', ['T1059.001', 'T1566.001'], { hits_7d: 3, agents_30d: 2, true_positives: 4, false_positives: 0, fp_rate: 0, can_block: true, block_blocker: null }),
	rule('RMM-F-0002', 'Cobalt Strike beacon', 'file', null, 'severe', 'high', 'block', ['T1071.001'], { hits_7d: 2, agents_30d: 2, true_positives: 2, fp_rate: 0, can_block: true, block_blocker: null }),
	rule('RMM-B-0031', 'Scheduled task created from a temp folder', 'behaviour', 'process', 'moderate', 'medium', 'audit', ['T1053.005'], { audit_hits_7d: 41, agents_30d: 9, false_positives: 3, true_positives: 1, fp_rate: 0.75 }),
	rule('RMM-B-0018', 'Credential dumping via comsvcs MiniDump', 'behaviour', 'process', 'severe', 'high', 'alert', ['T1003.001'], { first_seen: ago(60 * 24 * 3), can_block: false, block_blocker: 'it needs 7 days in general content first (audit history)' }),
	rule('RMM-B-0022', 'Shadow copies deleted', 'behaviour', 'process', 'severe', 'high', 'alert', ['T1490'], { override_mode: 'block', override_reason: 'Ransomware precursor; no legitimate use here', effective_mode: 'block', hits_7d: 1, agents_30d: 1, true_positives: 1, fp_rate: 0, can_block: true, block_blocker: null }),
	rule('RMM-B-0040', 'Unsigned driver loaded', 'behaviour', 'module', 'moderate', 'low', 'alert', ['T1014'], { override_mode: 'disabled', override_reason: 'Noisy on build servers', effective_mode: 'disabled', false_positives: 12, fp_rate: 1 })
];
const contentVersion = (id: string, version: string, stage: string, mins: number, o: Record<string, unknown> = {}) => ({
	id, version, sha256: Array.from({ length: 64 }, (_, i) => '0123456789abcdef'[(i * 7 + Number(version.replace(/\D/g, '').slice(-3)) * (i % 5 + 1)) % 16]).join(''), description: '', rule_count: 64, hashes: 18_204, stage, stage_reason: null,
	uploaded_by_name: 'Dana Admin', uploaded_at: ago(mins), stage_changed_at: ago(mins), agents: 0, ...o
});
const contentVersions = [
	contentVersion('cv-4', '2026.06.15.1', 'canary', 90, { description: 'Adds 2 rules for SharePoint web shells; tightens RMM-B-0031.', rule_count: 66, hashes: 18_377, agents: 0 }),
	contentVersion('cv-3', '2026.06.14.1', 'general', 60 * 26, { description: 'Cobalt Strike beacons, comsvcs MiniDump.', stage_changed_at: ago(60 * 2), stage_reason: 'Soaked 24 h on 1 canary client without problems', agents: 4 }),
	contentVersion('cv-2', '2026.06.12.1', 'rolled_back', 60 * 24 * 3, { description: 'Broader LOLBin rules.', rule_count: 63, stage_changed_at: ago(60 * 24 * 3 - 120), stage_reason: 'RMM-B-0029 fired on every msiexec install', uploaded_by_name: 'Terry Tech' }),
	contentVersion('cv-1', '2026.06.10.2', 'retired', 60 * 24 * 5, { description: 'Starter content.', rule_count: 58, hashes: 17_950, stage_changed_at: ago(60 * 2), stage_reason: 'Replaced by 2026.06.14.1', agents: 2 })
];
const av = (o: Record<string, unknown> = {}) => ({ realtime: 'block', scan_on_write: true, archive_depth: 5, database_max_age_hours: 72, ...o });
const dbSources = [
	{ name: 'content/yara', kind: 'yara', entries: 15 },
	{ name: 'yara-forge-core', kind: 'yara', entries: 3_000 },
	{ name: 'malwarebazaar-recent.csv', kind: 'sha256-list', entries: 1_043_844 },
	{ name: 'main.hdb', kind: 'clamav-hdb', entries: 2_366 }
];
const sigDb = (id: string, version: string, stage: string, mins: number, o: Record<string, unknown> = {}) => ({
	id, version, sha256: contentVersion(id, version, stage, mins).sha256.split('').reverse().join(''), size: 39_604_224, description: '', hashes: 1_046_210, yara_rules: 3_015,
	rule_count: 3_019, sources: dbSources, built_at: ago(mins + 15), stage, stage_reason: null, stored: true, uploaded_by_name: 'Dana Admin', uploaded_at: ago(mins),
	stage_changed_at: ago(mins), agents: 0, ...o
});
const signatureDatabases = [
	sigDb('sd-4', '2026.06.15.1', 'canary', 85, { description: 'Daily build: MalwareBazaar to 15 June, YARA Forge core 20260614.', hashes: 1_048_576, yara_rules: 3_022, rule_count: 3_026, size: 39_731_200 }),
	sigDb('sd-3', DB_GENERAL, 'general', 60 * 22, { description: 'Daily build.', stage_changed_at: ago(60 * 2), stage_reason: 'Soaked 24 h on 1 canary client without problems', agents: 4 }),
	sigDb('sd-2', '2026.06.12.1', 'rolled_back', 60 * 24 * 3, { description: 'Adds YARA Forge extended.', yara_rules: 7_912, rule_count: 7_916, size: 44_040_192, stored: false, stage_changed_at: ago(60 * 24 * 3 - 90), stage_reason: 'RMM-Y-0021 fired on /usr/bin/parallel on 9 machines', uploaded_by_name: 'Terry Tech' }),
	sigDb('sd-1', DB_OLD, 'retired', 60 * 24 * 5, { hashes: 980_112, yara_rules: 2_870, rule_count: 2_874, size: 37_311_488, stage_changed_at: ago(60 * 22), stage_reason: `Replaced by ${DB_GENERAL}`, agents: 1, sources: dbSources.slice(0, 3) })
];
const reputationSources = [
	{ source: 'db:2026.06.15.1', hashes: 1_048_576, added_at: ago(80) },
	{ source: 'list:malwarebazaar-full', hashes: 912_440, added_at: ago(60 * 24 * 2) },
	{ source: 'list:incident-2026-06', hashes: 14, added_at: ago(60 * 6) }
];
const rarePrograms = [
	{ sha256: '5d41c0a8e2f9b7d3c1a0e8f6d4b2a0c8e6f4d2b0a8c6e4f2d0b8a6c4e2f0d8b6', seen_on: 1, first_seen: ago(42), agents: [{ agent_id: 'a-3', hostname: 'acme-web01', client_name: 'Acme Corp', path: '/tmp/.ICE-unix/kworkerd' }] },
	{ sha256: '0c9e7a5b3d1f8e6c4a2b0d9f7e5c3a1b8d6f4e2c0a9b7d5f3e1c8a6b4d2f0e9c', seen_on: 1, first_seen: ago(60 * 5), agents: [{ agent_id: 'a-1', hostname: 'acme-dc01', client_name: 'Acme Corp', path: 'C:\\Users\\dana\\Downloads\\WinDirStat-2.0.1-setup.exe' }] },
	{ sha256: '7f1e3d5c7b9a1e3d5c7b9a2f4e6d8c0b2a4f6e8d0c2b4a6f8e0d2c4b6a8f0e2d', seen_on: 2, first_seen: ago(60 * 26), agents: [{ agent_id: 'a-5', hostname: 'globex-app01', client_name: 'Globex', path: '/opt/backup/bin/pg-dump-wrapper' }, { agent_id: 'a-6', hostname: 'globex-db01', client_name: 'Globex', path: '/opt/backup/bin/pg-dump-wrapper' }] }
];
const exclusions = [
	{ id: 'ex-1', client_id: null, client_name: null, kind: 'path', value: 'D:\\Backups\\', comment: 'Veeam repository; scanned by the backup server', created_by_name: 'Dana Admin', created_at: ago(60 * 24 * 20) },
	{ id: 'ex-2', client_id: 'c-acme', client_name: 'Acme Corp', kind: 'sha256', value: '7e3d1c9b5a7f2e4d6c8b0a1f3e5d7c9b2a4f6e8d0c1b3a5f7e9d2c4b6a8f0e1d', comment: 'restored from quarantine', created_by_name: 'Dana Admin', created_at: ago(60 * 24 * 5) },
	{ id: 'ex-3', client_id: 'c-globex', client_name: 'Globex', kind: 'process', value: 'pg_basebackup', comment: 'Nightly database backups', created_by_name: 'Terry Tech', created_at: ago(60 * 24 * 9) },
	{ id: 'ex-4', client_id: 'c-acme', client_name: 'Acme Corp', kind: 'rule', value: 'RMM-B-0031', comment: 'false positive (detection d-7)', created_by_name: 'Dana Admin', created_at: ago(60 * 8) }
];
const telemetryEvents = [...contextD5].sort((x, y) => Date.parse(y.ts) - Date.parse(x.ts));
function hunt(body: Record<string, unknown>) {
	const sha = body.sha256 as string | undefined;
	if (!sha && !body.text) return { status: 400, body: { error: 'search for something: text or a hash' } };
	return {
		status: 200,
		body: {
			hits: [
				{ agent_id: 'a-2', hostname: 'acme-fs01', client_name: 'Acme Corp', truncated: false, events: contextD5.filter((e) => e.kind === 'file' || (e.kind === 'process' && (e.process as { pid: number }).pid === 7012)) },
				{ agent_id: 'a-1', hostname: 'acme-dc01', client_name: 'Acme Corp', truncated: false, events: [ev(51210, 60 * 3, 'file', 'create', { process: proc(812, 3120, 'msedge.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'msedge.exe', 60 * 5, 'ACME\\dana'), file: { path: 'C:\\Users\\dana\\Downloads\\upd4412.exe', sha256: HASH_BEACON } })] }
			],
			searched: 4, offline: 1, errors: [{ agent_id: 'a-3', hostname: 'acme-web01', error: 'timed out after 10 s' }]
		}
	};
}

// --- policy management ------------------------------------------------------------------------
type Cfg = Record<string, unknown>;
interface PSet { id: string; parent_id: string | null; client_id: string | null; name: string; description: string; builtin: boolean }
const pset = (id: string, parent: string | null, name: string, o: Partial<PSet> = {}): PSet => ({ id, parent_id: parent, client_id: null, name, description: '', builtin: !id.startsWith('ps-'), ...o });
const policySets: PSet[] = [
	pset(SET.root, null, 'All devices'),
	pset(SET.win, SET.root, 'Windows'), pset(SET.linux, SET.root, 'Linux'), pset(SET.mac, SET.root, 'macOS'),
	pset(SET.winWs, SET.win, 'Windows workstations'), pset(SET.winSrv, SET.win, 'Windows servers'),
	pset(SET.linWs, SET.linux, 'Linux workstations'), pset(SET.linSrv, SET.linux, 'Linux servers'),
	pset(SET.macWs, SET.mac, 'macOS workstations'), pset(SET.macSrv, SET.mac, 'macOS servers'),
	pset(SET.dc, SET.winSrv, 'Domain controllers', { description: 'Never restart by themselves; patched by hand on Sundays.' }),
	pset(SET.acmeWin, SET.winSrv, 'Acme · Windows servers', { client_id: 'c-acme', description: 'Acme installs critical updates itself, two days late.' }),
	pset(SET.acmeTills, SET.winWs, 'Acme · Warehouse tills', { client_id: 'c-acme', description: 'Point-of-sale machines: Sunday night installs, ask before remote control.' }),
	pset(SET.web01, SET.linSrv, 'acme-web01', { client_id: 'c-acme', description: 'Customized for acme-web01' })
];
const C = '00000000-0000-4000-8002-0000000000';
const categories = [
	{ id: `${C}11`, name: 'Windows workstations', os_family: 'windows', platform: 'workstation', default_set_id: SET.winWs },
	{ id: `${C}12`, name: 'Windows servers', os_family: 'windows', platform: 'server', default_set_id: SET.winSrv },
	{ id: `${C}21`, name: 'Linux workstations', os_family: 'linux', platform: 'workstation', default_set_id: SET.linWs },
	{ id: `${C}22`, name: 'Linux servers', os_family: 'linux', platform: 'server', default_set_id: SET.linSrv },
	{ id: `${C}31`, name: 'macOS workstations', os_family: 'macos', platform: 'workstation', default_set_id: SET.macWs },
	{ id: `${C}32`, name: 'macOS servers', os_family: 'macos', platform: 'server', default_set_id: SET.macSrv },
	{ id: 'cat-kiosk', name: 'Kiosks', os_family: null, platform: null, default_set_id: SET.winWs, description: 'Shared machines in shops and warehouses' }
].map((c) => ({ description: '', ...c, builtin: c.id !== 'cat-kiosk', created_at: ago(60 * 24 * 30), updated_at: ago(60 * 24 * 30) }));
const assignments = [
	{ id: 'as-1', client_id: 'c-acme', site_id: null as string | null, category_id: `${C}12`, policy_set_id: SET.acmeWin, updated_at: ago(60 * 24 * 2) },
	{ id: 'as-2', client_id: 'c-acme', site_id: 's-acme-wh' as string | null, category_id: 'cat-kiosk', policy_set_id: SET.acmeTills, updated_at: ago(60 * 24) }
];
/** Where each agent sits: category (by hand?), pin, platform. */
const placement: Record<string, { cat: string; manual?: boolean; pin?: string; platform: 'workstation' | 'server' }> = {
	'a-1': { cat: `${C}12`, platform: 'server' }, 'a-2': { cat: `${C}12`, platform: 'server' }, 'a-3': { cat: `${C}22`, pin: SET.web01, platform: 'server' },
	'a-4': { cat: 'cat-kiosk', manual: true, platform: 'workstation' }, 'a-5': { cat: `${C}22`, platform: 'server' }, 'a-6': { cat: `${C}22`, platform: 'server' },
	'a-7': { cat: `${C}11`, platform: 'workstation' }
};
const setOf = (id: string) => policySets.find((x) => x.id === id)!;
function resolveSet(a: Agent): { set: string; reason: 'pin' | 'site' | 'client' | 'default'; assignment: string | null } {
	const pl = placement[a.id];
	if (pl.pin) return { set: pl.pin, reason: 'pin', assignment: null };
	const site = assignments.find((x) => x.site_id === a.site_id && x.category_id === pl.cat);
	if (site) return { set: site.policy_set_id, reason: 'site', assignment: site.id };
	const cl = assignments.find((x) => x.client_id === a.client_id && !x.site_id && x.category_id === pl.cat);
	if (cl) return { set: cl.policy_set_id, reason: 'client', assignment: cl.id };
	return { set: categories.find((c) => c.id === pl.cat)!.default_set_id, reason: 'default', assignment: null };
}
for (const a of agents) {
	const pl = placement[a.id];
	const r = resolveSet(a);
	Object.assign(a, { platform: pl.platform, category_id: pl.cat, category_name: categories.find((c) => c.id === pl.cat)!.name, policy_set_id: r.set, policy_set_name: setOf(r.set).name });
}
const agentSet = (a: Agent) => (a as Agent & { policy_set_id: string }).policy_set_id;

const PATCH_ITEM = '00000000-0000-4000-8000-000000000001';
const SECURITY_ITEM = '00000000-0000-4000-8000-000000000002';
const REMOTE_ITEM = '00000000-0000-4000-8000-000000000003';
const AGENT_ITEM = '00000000-0000-4000-8000-000000000004';
const TRAY_ITEM = '00000000-0000-4000-8000-000000000007';
interface PItem { id: string; set: string; module: string; name: string; enabled: boolean; config: Cfg; client_id: string | null; site_id: string | null; excluded: { id: string; hostname: string }[] }
const alertSet: Record<string, string> = { 'p-off': SET.root, 'p-disk': SET.root, 'p-cpu': SET.root, 'p-svc': SET.root, 'p-job': SET.linux, 'p-log': SET.linux };
const alertConfig = (p: (typeof policies)[number]): Cfg => ({
	kind: p.kind, params: p.params, severity: p.severity, channel_ids: p.channel_ids, notify_resolved: p.notify_resolved, renotify_minutes: p.renotify_minutes,
	ticket_board_id: null, ticket_priority: 3, ticket_auto_resolve: false, run_script_id: null
});
const items: PItem[] = [
	...policies.map((p) => ({ id: p.id, set: alertSet[p.id], module: 'alert', name: p.name, enabled: p.enabled, config: alertConfig(p), client_id: p.client_id, site_id: p.site_id, excluded: p.excluded })),
	{ id: 'p-veeam', set: SET.acmeWin, module: 'alert', name: 'Backup service stopped', enabled: true, client_id: 'c-acme', site_id: null, excluded: [],
		config: { kind: 'service', params: { services: ['VeeamBackupSvc'], auto_only: false, exclude: [] }, severity: 'critical', channel_ids: ['ch-mail'], notify_resolved: true, renotify_minutes: null, ticket_board_id: 'b-alerts', ticket_priority: 2, ticket_auto_resolve: true, run_script_id: null } },
	...schedules.map((x) => ({ id: x.id, set: x.set_id, module: 'schedule', name: x.name, enabled: x.enabled, client_id: x.client_id, site_id: x.site_id, excluded: [], config: { script_id: x.script_id, cron: x.cron, timezone: x.timezone, args: x.args, ...(x.id === 'sc-1' ? { params: { min_pct: '95' } } : {}), timeout_secs: x.timeout_secs, retain_days: x.retain_days } })),
	{ id: 'sw-req', set: SET.acmeWin, module: 'software', name: 'Firefox on Acme Windows devices', enabled: true, client_id: 'c-acme', site_id: null, excluded: [], config: { package_id: 'sw-ff', state: 'latest', bootstrap_choco: false, window: null } },
	{ id: 'au-welcome', set: SET.root, module: 'automation', name: 'Welcome new devices', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { trigger: 'enrollment', script_id: 's-disk', args: [], timeout_secs: null, offline_minutes: null, alert_kind: null, retry_failed: true, max_attempts: 3, retry_minutes: 30, cooldown_minutes: 60, max_runs_per_hour: 100, respect_window: false, retain_days: 30 } },
	{ id: 'au-addon', set: SET.root, module: 'automation', name: 'Install the monitoring add-on', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { trigger: 'run_once', script_id: 's-upd', args: ['--quiet'], timeout_secs: 300, offline_minutes: null, alert_kind: null, retry_failed: true, max_attempts: 3, retry_minutes: 30, cooldown_minutes: 60, max_runs_per_hour: 50, respect_window: true, retain_days: 30 } },
	{ id: 'au-back', set: SET.win, module: 'automation', name: 'Resync after a long absence', enabled: true, client_id: 'c-acme', site_id: null, excluded: [],
		config: { trigger: 'agent_online', script_id: 's-spool', args: [], timeout_secs: null, offline_minutes: 120, alert_kind: null, retry_failed: false, max_attempts: 3, retry_minutes: 30, cooldown_minutes: 240, max_runs_per_hour: 20, respect_window: false, retain_days: 14 } },
	{ id: 'au-disk', set: SET.linux, module: 'automation', name: 'Clean up when the disk fills', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { trigger: 'alert_opened', script_id: 's-disk', args: [], timeout_secs: 120, offline_minutes: null, alert_kind: 'disk', retry_failed: false, max_attempts: 3, retry_minutes: 30, cooldown_minutes: 60, max_runs_per_hour: 100, respect_window: true, retain_days: 30 } },
	{ id: 'au-tag', set: SET.root, module: 'automation', name: 'Set up pilot machines', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { trigger: 'tag_added', script_id: 's-upd', args: ['--pilot'], timeout_secs: null, offline_minutes: null, alert_kind: null, tag_id: 'tg-pilot', field_id: null, field_value: null, retry_failed: false, max_attempts: 3, retry_minutes: 30, cooldown_minutes: 60, max_runs_per_hour: 100, respect_window: false, retain_days: 30 } },
	{ id: 'au-field', set: SET.root, module: 'automation', name: 'Gold support onboarding', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { trigger: 'field_changed', script_id: 's-disk', args: [], timeout_secs: null, offline_minutes: null, alert_kind: null, tag_id: null, field_id: 'cf-tier', field_value: 'Gold', retry_failed: false, max_attempts: 3, retry_minutes: 30, cooldown_minutes: 60, max_runs_per_hour: 100, respect_window: false, retain_days: 30 } },
	{ id: PATCH_ITEM, set: SET.root, module: 'patch', name: 'Patching', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { auto_approve_severities: [], auto_approve_categories: ['security', 'critical', 'definition'], deferral_days: 0, auto_install: false, reboot_policy: 'never', window: null } },
	{ id: SECURITY_ITEM, set: SET.root, module: 'security', name: 'Security', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { sensor_enabled: true, quick_scan_hours: 24, full_scan_days: 7, auto_quarantine: true, prevention: true, canaries: true, telemetry_mb: 256, realtime: 'block', scan_on_write: true, archive_depth: 5, database_max_age_hours: 72 } },
	{ id: REMOTE_ITEM, set: SET.root, module: 'remote_access', name: 'Remote access', enabled: true, client_id: null, site_id: null, excluded: [], config: { desktop_enabled: true, desktop_consent: false, shell_enabled: true, files_enabled: true } },
	{ id: AGENT_ITEM, set: SET.root, module: 'agent', name: 'Agent', enabled: true, client_id: null, site_id: null, excluded: [], config: { auto_update: true } },
	{ id: TRAY_ITEM, set: SET.root, module: 'tray', name: 'Tray app', enabled: true, client_id: null, site_id: null, excluded: [],
		config: { enabled: true, request_help: true, contact_card: true, screenshot_default: true, links: [{ label: 'Service status', url: 'https://status.example.com' }] } }
];
const overrides: { item: string; set: string; enabled: boolean | null; config: Cfg }[] = [
	{ item: PATCH_ITEM, set: SET.acmeWin, enabled: null, config: { auto_approve_severities: ['critical'], deferral_days: 2, auto_install: true, reboot_policy: 'if_required' } },
	{ item: 'p-disk', set: SET.acmeWin, enabled: null, config: { params: { threshold: 95 }, severity: 'warning' } },
	{ item: PATCH_ITEM, set: SET.acmeTills, enabled: null, config: { auto_install: true, reboot_policy: 'always', window: { days: [0], start: '02:00', minutes: 180, tz: 'site' } } },
	{ item: REMOTE_ITEM, set: SET.acmeTills, enabled: null, config: { desktop_consent: true } },
	{ item: SECURITY_ITEM, set: SET.linSrv, enabled: null, config: { canaries: false, telemetry_mb: 512 } },
	{ item: SECURITY_ITEM, set: SET.web01, enabled: null, config: { prevention: false, archive_depth: 3 } },
	{ item: 'p-off', set: SET.dc, enabled: null, config: { renotify_minutes: 30 } },
	{ item: 'au-addon', set: SET.winSrv, enabled: null, config: { max_runs_per_hour: 10, respect_window: false } },
	{ item: 'p-svc', set: SET.web01, enabled: false, config: {} },
	{ item: AGENT_ITEM, set: SET.winSrv, enabled: null, config: { auto_update: false } },
	{ item: PATCH_ITEM, set: SET.dc, enabled: null, config: { auto_install: false, reboot_policy: 'never' } }
];

const isObj = (v: unknown): v is Cfg => typeof v === 'object' && v !== null && !Array.isArray(v);
/** The server's merge rule: objects merge key by key, everything else replaces. */
function merge(base: unknown, over: unknown): unknown {
	if (!isObj(base) || !isObj(over)) return over;
	const out: Cfg = { ...base };
	for (const [k, v] of Object.entries(over)) out[k] = k in base ? merge(base[k], v) : v;
	return out;
}
/** Which set each leaf's value comes from (policy::field_sources). */
function fieldSources(origin: string, config: Cfg, ovs: { set: string; config: Cfg }[]): Record<string, string> {
	const out: Record<string, string> = {};
	const leaves = (v: unknown, prefix: string) => {
		if (isObj(v) && Object.keys(v).length) for (const [k, x] of Object.entries(v)) leaves(x, prefix ? `${prefix}.${k}` : k);
		else if (prefix) out[prefix] = origin;
	};
	leaves(config, '');
	const apply = (o: Cfg, prefix: string, set: string) => {
		for (const [k, v] of Object.entries(o)) {
			const p = prefix ? `${prefix}.${k}` : k;
			if (isObj(v) && Object.keys(v).length) {
				delete out[p];
				apply(v, p, set);
			} else {
				for (const key of Object.keys(out)) if (key.startsWith(`${p}.`)) delete out[key];
				out[p] = set;
			}
		}
	};
	for (const o of ovs) apply(o.config, '', o.set);
	return out;
}
function chainOf(id: string): PSet[] {
	const out: PSet[] = [];
	for (let s: PSet | undefined = setOf(id); s; s = s.parent_id ? setOf(s.parent_id) : undefined) out.unshift(s);
	return out;
}
const moduleOrder = ['alert', 'schedule', 'software', 'automation', 'patch', 'security', 'remote_access', 'agent', 'tray'];
function itemView(it: PItem, chain: PSet[], agent?: Agent) {
	const ids = chain.map((c) => c.id);
	const at = ids.indexOf(it.set);
	if (at < 0) return null;
	const here = ids[ids.length - 1];
	const ovs = overrides.filter((o) => o.item === it.id && ids.indexOf(o.set) > at).sort((x, y) => ids.indexOf(x.set) - ids.indexOf(y.set));
	let config: unknown = it.config;
	let enabled = it.enabled;
	for (const o of ovs) {
		config = merge(config, o.config);
		if (o.enabled != null) enabled = o.enabled;
	}
	const sources = fieldSources(it.set, it.config, ovs);
	sources.enabled = [...ovs].reverse().find((o) => o.enabled != null)?.set ?? it.set;
	const mine = ovs.find((o) => o.set === here);
	const client = clients.find((c) => c.id === it.client_id);
	const site = sites.find((x) => x.id === it.site_id);
	const sched = schedules.find((x) => x.id === it.id);
	return {
		id: it.id, module: it.module, name: it.name, origin_set_id: it.set, origin_set_name: setOf(it.set).name,
		status: it.set === here ? 'defined' : mine ? 'overridden' : 'inherited', enabled, config, item_enabled: it.enabled, item_config: it.config, sources,
		override: mine ? { enabled: mine.enabled, config: mine.config, updated_at: ago(60 * 24) } : null,
		limit: { client_id: it.client_id, client_name: client?.name ?? null, site_id: it.site_id, site_name: site?.name ?? null, excluded: it.excluded },
		editable: true, overridable: it.set !== here,
		open_alerts: alerts.filter((x) => x.policy_id === it.id && x.state !== 'resolved' && (!agent || x.agent_id === agent.id)).length,
		schedule: sched ? { next_run_at: sched.next_run_at, last_run_at: sched.last_run_at } : null,
		runs: it.module === 'automation' ? runCounts(automationRuns.filter((r) => r.item_id === it.id && (!agent || r.agent_id === agent.id))) : null,
		...(agent ? { applies: (!it.client_id || it.client_id === agent.client_id) && (!it.site_id || it.site_id === agent.site_id) && !it.excluded.some((x) => x.id === agent.id), excluded: it.excluded.some((x) => x.id === agent.id) } : {})
	};
}
function itemViews(chain: PSet[], agent?: Agent) {
	return items
		.map((it) => itemView(it, chain, agent))
		.filter((v): v is NonNullable<typeof v> => !!v)
		.sort((x, y) => moduleOrder.indexOf(x.module) - moduleOrder.indexOf(y.module) || x.name.toLowerCase().localeCompare(y.name.toLowerCase()));
}
function setRow(x: PSet) {
	const mine = items.filter((i) => i.set === x.id);
	const ovs = overrides.filter((o) => o.set === x.id);
	return {
		...x, client_name: clients.find((c) => c.id === x.client_id)?.name ?? null, depth: chainOf(x.id).length - 1,
		devices: agents.filter((a) => agentSet(a) === x.id).length, items: mine.length, overrides: ovs.length,
		defines: [...new Set(mine.map((i) => i.module))], overrides_modules: [...new Set(ovs.map((o) => items.find((i) => i.id === o.item)!.module))],
		default_for: categories.filter((c) => c.default_set_id === x.id).map((c) => c.id), created_at: ago(60 * 24 * 30), updated_at: ago(60 * 24 * 2)
	};
}
const chainEntry = (x: PSet) => ({ id: x.id, name: x.name, client_id: x.client_id, builtin: x.builtin });
const setSort = (a: PSet, b: PSet) => Number(b.builtin) - Number(a.builtin) || Number(!!a.client_id) - Number(!!b.client_id) || a.name.toLowerCase().localeCompare(b.name.toLowerCase());
function agentPolicy(a: Agent) {
	const pl = placement[a.id];
	const r = resolveSet(a);
	const chain = chainOf(r.set);
	const cat = categories.find((c) => c.id === pl.cat)!;
	return {
		agent_id: a.id, hostname: a.hostname, client_id: a.client_id, site_id: a.site_id, platform: pl.platform,
		category: { id: cat.id, name: cat.name, builtin: cat.builtin, manual: !!pl.manual }, set: chainEntry(setOf(r.set)), reason: r.reason, assignment_id: r.assignment,
		pin: pl.pin ? chainEntry(setOf(pl.pin)) : null, chain: chain.map(chainEntry), policies: itemViews(chain, a)
	};
}
function agentPatchPolicy(a: Agent, site: { days: number[] | null; start: string | null; minutes: number | null; tz: string; open_now: boolean; next_start: string | null }) {
	const set = agentSet(a);
	const eff = itemView(items.find((i) => i.id === PATCH_ITEM)!, chainOf(set))!.config as Cfg & { window: { days: number[]; start: string; minutes: number; tz: string } | null };
	const own = !!eff.window;
	const window = eff.window ? { ...eff.window, tz: eff.window.tz === 'site' ? site.tz : eff.window.tz, open_now: false, next_start: '2026-06-21T07:00:00.000Z' } : site;
	return { ...eff, id: PATCH_ITEM, set_id: set, source: setOf(set).name, own_window: own, window };
}
/** Runs of the automations: the device states `/policy-items/{id}/runs` and `/agents/{id}/automations` report. */
type RunStatus = 'waiting' | 'pending' | 'succeeded' | 'failed' | 'skipped';
const autoRun = (id: string, item: string, agent: number, trigger: string, status: RunStatus, reason: string | null, mins: number, attempts = 1, job: string | null = null, exit: number | null = null) => {
	const a = agents[agent - 1];
	const it = items.find((i) => i.id === item)!;
	return {
		id, item_id: item, item_name: it.name, agent_id: a.id, hostname: a.hostname, trigger, status, reason, context: {}, job_id: status === 'waiting' || status === 'skipped' ? null : (job ?? `j-${agent}`),
		script_id: it.config.script_id as string, script_name: scripts.find((x) => x.id === it.config.script_id)?.name ?? null, exit_code: exit, attempts,
		created_at: ago(mins + 1), started_at: status === 'waiting' || status === 'skipped' ? null : ago(mins), finished_at: status === 'succeeded' || status === 'failed' || status === 'skipped' ? ago(mins - 0.2) : null
	};
};
const automationRuns = [
	autoRun('ar-1', 'au-addon', 1, 'run_once', 'succeeded', null, 60 * 5, 1, 'j-1', 0),
	autoRun('ar-2', 'au-addon', 2, 'run_once', 'failed', 'failed', 60 * 3, 2, 'j-2', 1),
	autoRun('ar-3', 'au-addon', 3, 'run_once', 'succeeded', null, 60 * 5, 1, 'j-3', 0),
	autoRun('ar-4', 'au-addon', 4, 'run_once', 'pending', null, 20),
	autoRun('ar-5', 'au-addon', 5, 'run_once', 'waiting', 'maintenance_window', 90),
	autoRun('ar-6', 'au-addon', 6, 'run_once', 'succeeded', null, 60 * 4, 1, 'j-6', 0),
	autoRun('ar-7', 'au-welcome', 7, 'enrollment', 'succeeded', null, 60 * 24 * 2, 1, 'j-7', 0),
	autoRun('ar-8', 'au-disk', 3, 'alert_opened', 'succeeded', null, 60 * 2, 1, 'j-3', 0),
	autoRun('ar-9', 'au-disk', 3, 'alert_opened', 'skipped', 'cooldown', 30),
	autoRun('ar-10', 'au-back', 1, 'agent_online', 'succeeded', null, 60 * 26, 1, 'j-1', 0),
	autoRun('ar-11', 'au-back', 1, 'agent_online', 'skipped', 'rate_limited', 60 * 8),
	{ ...autoRun('ar-12', 'au-tag', 3, 'tag_added', 'succeeded', null, 60 * 3, 1, 'j-3', 0), context: { tag_id: 'tg-pilot', tag: 'Pilot ring', source: 'user' } },
	{ ...autoRun('ar-13', 'au-field', 3, 'field_changed', 'succeeded', null, 60 * 9, 1, 'j-3', 0), context: { field: 'support_tier', from: 'Silver', to: 'Gold', source: 'user' } },
	{ ...autoRun('ar-14', 'au-field', 3, 'field_changed', 'skipped', 'own_write', 60 * 9 - 2), context: { field: 'support_tier', from: 'Gold', to: 'Platinum', source: 'script' } }
];
const runCounts = (rows: typeof automationRuns) =>
	Object.fromEntries((['waiting', 'pending', 'succeeded', 'failed', 'skipped'] as RunStatus[]).map((st) => [st, rows.filter((r) => r.status === st).length])) as Record<RunStatus, number>;
const scheduleOut = (x: (typeof schedules)[number]) => ({ ...x, set_name: setOf(x.set_id).name });
/** GET routes of the policy API; undefined when `path` isn't one, null for an unknown set. */
function policyRoute(path: string, q: URLSearchParams): unknown {
	let m: RegExpMatchArray | null;
	if (path === '/policy-sets') {
		const cid = q.get('client_id');
		return [...policySets].sort(setSort).filter((x) => !cid || !x.client_id || x.client_id === cid).map(setRow);
	}
	if ((m = path.match(/^\/policy-sets\/([^/]+)$/))) {
		const x = policySets.find((y) => y.id === m![1]);
		if (!x) return null;
		const chain = chainOf(x.id);
		return { ...setRow(x), chain: chain.map(chainEntry), children: policySets.filter((y) => y.parent_id === x.id).sort(setSort).map(setRow), policies: itemViews(chain), editable: true };
	}
	if ((m = path.match(/^\/policy-sets\/([^/]+)\/agents$/))) {
		const list = agents.filter((a) => agentSet(a) === m![1]).map((a) => ({
			id: a.id, hostname: a.hostname, online: a.online, os_family: a.os_family, platform: placement[a.id].platform, client_id: a.client_id, client_name: a.client_name,
			site_id: a.site_id, site_name: a.site_name, category_id: placement[a.id].cat, category_name: categories.find((c) => c.id === placement[a.id].cat)!.name, reason: resolveSet(a).reason
		}));
		return page(list, Number(q.get('limit') ?? 50));
	}
	if ((m = path.match(/^\/policy-items\/([^/]+)\/runs$/))) {
		const all = automationRuns.filter((r) => r.item_id === m![1]);
		const only = q.get('status');
		return { counts: runCounts(all), runs: only ? all.filter((r) => r.status === only) : all };
	}
	if ((m = path.match(/^\/agents\/([^/]+)\/automations$/))) return [...automationRuns].filter((r) => r.agent_id === m![1]).reverse();
	if ((m = path.match(/^\/policy-items\/([^/]+)$/))) {
		const it = items.find((i) => i.id === m![1]);
		return it ? itemView(it, chainOf(it.set)) : null;
	}
	if (path === '/device-categories') return categories.map((c) => ({ ...c, default_set_name: setOf(c.default_set_id).name, devices: agents.filter((a) => placement[a.id].cat === c.id).length }));
	if (path === '/policy-assignments') {
		return assignments
			.filter((x) => !q.get('client_id') || x.client_id === q.get('client_id'))
			.map((x) => ({ ...x, client_name: clients.find((c) => c.id === x.client_id)!.name, site_name: sites.find((y) => y.id === x.site_id)?.name ?? null, category_name: categories.find((c) => c.id === x.category_id)!.name, policy_set_name: setOf(x.policy_set_id).name }));
	}
	if ((m = path.match(/^\/agents\/([^/]+)\/policy$/))) return agentPolicy(agents.find((a) => a.id === m![1])!);
	return undefined;
}

// --- documentation and the vault ------------------------------------------------------------
const CAT = '00000000-0000-4000-8003-00000000000';
const docCategories = ['Network', 'Infrastructure', 'Accounts & access', 'Applications', 'Backup & recovery', 'Vendors', 'Procedures', 'Onboarding'].map((name, i) => ({ id: `${CAT}${i + 1}`, name, position: i }));
const V = { fw: '6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111', m365: '1d0b9a3e-2c4f-4e8a-9b71-5e6f7a8b9c01', wifi: '2e1c8b4f-3d5a-4f9b-8c62-6f7a8b9c0d12', sw: '3f2d7c5a-4e6b-4a0c-9d53-7a8b9c0d1e23', veeam: '4a3e6d6b-5f7c-4b1d-8e44-8b9c0d1e2f34' };
const vaultItems = [
	{ id: V.fw, name: 'FortiGate admin', username: 'admin', url: 'https://10.0.0.1:4443', has_password: true, has_totp: true, has_notes: false, docs: 1, password_changed_at: ago(60 * 24 * 41) },
	{ id: V.m365, name: 'Microsoft 365 global admin', username: 'admin@acmecorp.onmicrosoft.com', url: 'https://admin.microsoft.com', has_password: true, has_totp: true, has_notes: true, docs: 1, password_changed_at: ago(60 * 24 * 12) },
	{ id: V.wifi, name: 'Staff Wi-Fi key', username: '', url: '', has_password: true, has_totp: false, has_notes: false, docs: 2, password_changed_at: ago(60 * 24 * 160) },
	{ id: V.sw, name: 'Core switch', username: 'manager', url: '10.0.0.2', has_password: true, has_totp: false, has_notes: false, docs: 0, password_changed_at: ago(60 * 24 * 300) },
	{ id: V.veeam, name: 'Veeam console', username: 'ACME\\svc-backup', url: 'rdp://acme-backup01', has_password: true, has_totp: false, has_notes: true, docs: 1, password_changed_at: null },
	{ id: '6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a1f0', name: 'BitLocker recovery: acme-dc01 C:', username: '{3F2A6C1D-4B8E-4F0A-9C21-7D5E8B1A0C33}', url: '', has_password: true, has_totp: false, has_notes: false, docs: 0, password_changed_at: ago(60 * 24 * 3),
		managed_kind: 'disk_recovery', agent_id: 'a-1', agent_hostname: 'acme-dc01', managed_state: null }
].map((v, i) => ({ managed_kind: null, agent_id: null, agent_hostname: null, managed_state: null, ...v, client_id: 'c-acme', updated_at: ago(60 * (30 + i * 200)), updated_by_name: i % 2 ? 'Terry Tech' : 'Dana Admin' }));
const vaultDetail = (id: string) => {
	const v = vaultItems.find((x) => x.id === id)!;
	return {
		...v,
		linked_docs: v.docs ? clientDocs.filter((d) => d.body.includes(id)).map((d) => ({ id: d.id, title: d.title })) : [],
		history: id === V.fw ? [{ id: 12, replaced_at: ago(60 * 24 * 41), replaced_by_name: 'Dana Admin' }, { id: 7, replaced_at: ago(60 * 24 * 220), replaced_by_name: 'Terry Tech' }] : []
	};
};
const networkBody = `Head office and warehouse share one internet line; the warehouse hangs off a site-to-site tunnel.

## Internet

\`\`\`fields
ISP: Northwind Fibre (business 500/500)
Circuit / account number: NWF-204-88173
Public IP addresses: 203.0.113.18/29
ISP support: +1 555 0144, option 2
\`\`\`

## Addressing

\`\`\`fields
LAN subnet: 10.0.0.0/22
Gateway: 10.0.0.1
DNS servers: 10.0.0.10 (acme-dc01), 1.1.1.1
DHCP range: 10.0.1.100 - 10.0.1.250
Static range:
\`\`\`

## VLANs

| VLAN | Name | Subnet | Purpose |
|---|---|---|---|
| 1 | Default | 10.0.0.0/24 | Servers and printers |
| 20 | Staff | 10.0.1.0/24 | Workstations, staff Wi-Fi |
| 30 | Guest | 192.168.30.0/24 | Guest Wi-Fi, internet only |
| 40 | Tills | 10.0.3.0/24 | Warehouse point of sale |

## Firewall

The FortiGate sits in the comms cupboard on the first floor. Firmware updates go in the Sunday window, see [Change procedure](doc:d-change).

\`\`\`credential
item: vault:${V.fw}
label: Firewall admin
\`\`\`

\`\`\`callout warning
Rebooting the firewall drops the **warehouse tunnel** and every till with it. Call Ann Lopez first, and never between 07:00 and 19:00.
\`\`\`

## Switches

| Name | Model | Management IP | Location |
|---|---|---|---|
| core-sw01 | Aruba 2930F-48G | 10.0.0.2 | Comms cupboard |
| wh-sw01 | Aruba 2530-24G | 10.0.2.2 | Warehouse office |

\`\`\`credential
label: Switch admin
\`\`\`

## Servers

\`\`\`device
agent: a-1
\`\`\`

\`\`\`device
agent: a-2
\`\`\`

## Checks after a change

- [x] Both sites reach the file server
- [x] Tills can take a card payment
- [ ] Guest Wi-Fi can't reach 10.0.0.0/22

Staff Wi-Fi uses the [Staff Wi-Fi key](vault:${V.wifi}); the guest key is on the sign at reception.

\`\`\`
diagnose vpn tunnel list name warehouse
execute ping-options source 10.0.0.1
\`\`\`
`;
const clientDocs = [
	{ id: 'd-network', title: 'Network overview', cat: 0, body: networkBody, mins: 95, by: 'Dana Admin', revisions: 6 },
	{ id: 'd-wifi', title: 'Wi-Fi', cat: 0, body: `\`\`\`credential\nitem: vault:${V.wifi}\n\`\`\`\n`, mins: 60 * 24 * 9, by: 'Terry Tech', revisions: 1 },
	{ id: 'd-dc', title: 'acme-dc01', cat: 1, body: '```device\nagent: a-1\n```\n', mins: 60 * 24 * 30, by: 'Dana Admin', revisions: 3 },
	{ id: 'd-m365', title: 'Microsoft 365 tenant', cat: 2, body: `\`\`\`credential\nitem: vault:${V.m365}\n\`\`\`\n`, mins: 60 * 5, by: 'Terry Tech', revisions: 2 },
	{ id: 'd-backup', title: 'Backup and recovery', cat: 4, body: `\`\`\`credential\nitem: vault:${V.veeam}\n\`\`\`\n`, mins: 60 * 24 * 60, by: 'Dana Admin', revisions: 0 },
	{ id: 'd-change', title: 'Change procedure', cat: 6, body: 'Sunday 22:00 to 02:00.', mins: 60 * 24 * 90, by: 'Dana Admin', revisions: 0 },
	{ id: 'd-printer', title: 'Second-floor printer quirks', cat: -1, body: 'Turn it off and on again.', mins: 60 * 24 * 3, by: 'Terry Tech', revisions: 0 }
].map((d) => ({
	id: d.id, client_id: 'c-acme', title: d.title, category_id: d.cat >= 0 ? docCategories[d.cat].id : null, category: d.cat >= 0 ? docCategories[d.cat].name : '',
	body: d.body, updated_by_name: d.by, updated_at: ago(d.mins), revisions: d.revisions
}));
const docRow = (d: (typeof clientDocs)[number]) => ({ ...d, body: null });
const docDetail = (d: (typeof clientDocs)[number]) => ({
	...d,
	history: Array.from({ length: d.revisions }, (_, i) => ({ id: 40 - i, title: d.title, edited_by: i % 2 ? 'Terry Tech' : 'Dana Admin', edited_at: ago(60 * 24 * (i * 9 + 2)) })),
	credentials: vaultItems.filter((v) => d.body.includes(v.id)),
	credentials_hidden: false,
	// Newest first.
	tickets: tickets.filter((t) => ticketDocs[t.id]?.includes(d.id)).sort((x, y) => Date.parse(y.created_at as string) - Date.parse(x.created_at as string))
		.map((t) => ({ id: t.id, number: t.number, subject: t.subject, status: t.status_name, status_category: t.status_category, updated_at: t.updated_at }))
});
const TPL = '00000000-0000-4000-8004-00000000000';
const docTemplates = [
	['Network overview', 0, 'Internet, addressing, VLANs, firewall and switches.'],
	['Wi-Fi', 0, 'SSIDs, the controller and the keys for staff and guests.'],
	['Server', 1, 'One server: role, hardware, services, access and maintenance.'],
	['Microsoft 365 tenant', 2, 'Tenant details, admin accounts, security baseline and domains.'],
	['Line-of-business application', 3, 'An application the client runs on: vendor, licences, access, installs and updates.'],
	['Backup and recovery', 4, 'What is backed up, where, how to restore, and the restore tests.'],
	['Vendor', 5, 'A supplier: account, support contacts, portal and escalation.'],
	['New user procedure', 6, 'The steps for a new starter at this client.'],
	['Client onboarding checklist', 7, 'Everything to collect and set up when a new client signs.']
].map(([name, cat, description], i) => ({
	id: `${TPL}${i + 1}`, name, category_id: docCategories[cat as number].id, category: docCategories[cat as number].name, description,
	body: null as string | null, updated_by_name: i === 2 ? 'Dana Admin' : null, updated_at: ago(60 * 24 * (i === 2 ? 4 : 40))
}));
const categoryOut = (c: (typeof docCategories)[number]) => ({ ...c, docs: clientDocs.filter((d) => d.category_id === c.id).length, templates: docTemplates.filter((t) => t.category_id === c.id).length });

const admin = { id: 'u-1', email: 'dana@northwind.example', name: 'Dana Admin', role: 'admin', totp_enabled: true, mfa_setup_required: false, client_ids: null, preferences: {}, permissions: ['security.read', 'security.respond', 'security.manage', 'vault.read', 'vault.manage'] };

// --- Network discovery and SNMP devices ------------------------------------------------------------
const netDev = (n: number, name: string, kind: string, host: string, state: 'up' | 'down', extra: Record<string, unknown> = {}) => ({
	id: `nd-${n}`, site_id: 's-acme-hq', site_name: 'Head office', client_id: 'c-acme', client_name: 'Acme Corp', name, host, port: 161, credential_id: 'nc-1', credential_name: 'Switches (read-only)',
	kind, enabled: true, poll_secs: null, sys_descr: null as string | null, sys_name: name.toLowerCase().replace(/ /g, '-'), sys_object_id: '1.3.6.1.4.1.9.1.1208', sys_location: 'Comms room, level 1', vendor: null as string | null,
	mac: null as string | null, state, state_since: ago(state === 'down' ? 47 : 60 * 24 * 12), last_poll_at: ago(state === 'down' ? 0 : 2), last_ok_at: state === 'down' ? ago(47) : ago(2),
	last_error: state === 'down' ? 'timeout after 3 tries' : null, rtt_ms: state === 'down' ? null : 3, uptime_secs: state === 'down' ? null : 86400 * 41 + 3600 * 5, cpu_percent: null as number | null, mem_used: null as number | null,
	mem_total: null as number | null, storage: [] as unknown[], supplies: [] as unknown[], created_at: ago(60 * 24 * 30), agent_id: 'a-1', agent_hostname: 'acme-dc01', agent_online: true,
	open_alerts: state === 'down' ? 1 : 0, interfaces: 0, interfaces_up: 0, ...extra
});
const netPorts = Array.from({ length: 8 }, (_, i) => ({
	if_index: i + 1, name: i === 7 ? 'Gi1/0/48' : `Gi1/0/${i + 1}`, descr: `GigabitEthernet1/0/${i + 1}`, alias: ['Uplink to firewall', 'Reception PC', 'Accounts PC', '', 'Wi-Fi AP lobby', 'Meeting room', '', 'Spare'][i], if_type: 6,
	speed_bps: 1_000_000_000, admin_status: i === 7 ? 2 : 1, oper_status: [1, 1, 1, 2, 1, 1, 2, 2][i], status_since: ago(60 * 24 * (i + 2)), monitored: i !== 7 && [1, 1, 1, 0, 1, 1, 0, 0][i] === 1,
	in_bps: [i === 0 ? 182_000_000 : 3_400_000 * i, 0][oper(i)], out_bps: [i === 0 ? 96_000_000 : 1_100_000 * i, 0][oper(i)], util_pct: i === 0 ? 18 : oper(i) ? null : 0.3 * i,
	in_errors: i === 4 ? 312 : 0, out_errors: 0, in_discards: i === 0 ? 14 : 0, out_discards: 0, last_at: ago(2)
}));
function oper(i: number) {
	return [0, 0, 0, 1, 0, 0, 1, 1][i];
}
// --- uptime monitors and backup jobs ------------------------------------------------------------
const monitorBase = { runner: 'agent', interval_secs: 60, timeout_secs: 10, enabled: true, fail_count: 0, cert: null as unknown, cert_not_after: null as string | null, last_value: null as number | null, created_at: ago(60 * 24 * 40), open_alerts: 0 };
const uptimeMonitors = [
	{ ...monitorBase, id: 'um-web', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-hq', site_name: 'Head office', name: 'Acme website', kind: 'http', config: { url: 'https://www.acme.example/', method: 'get', statuses: [], keyword: 'Welcome', keyword_absent: false, verify_tls: true }, target: 'https://www.acme.example/', agent_id: null, runner_agent_id: 'a-1', runner_hostname: 'acme-dc01', runner_online: true, state: 'up', state_since: ago(60 * 24 * 6), last_at: ago(1), last_ms: 182, last_message: 'HTTP 200', last_value: 200, cert_not_after: ago(-60 * 24 * 61), cert: { subject: 'CN=www.acme.example', issuer: 'C=US, O=Let’s Encrypt, CN=R11', sans: ['www.acme.example', 'acme.example'], not_before: ago(60 * 24 * 29), not_after: ago(-60 * 24 * 61), untrusted: null }, uptime_24h: 100, uptime_30d: 99.97 },
	{ ...monitorBase, id: 'um-vpn', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-hq', site_name: 'Head office', name: 'VPN gateway', kind: 'tls', config: { host: 'vpn.acme.example', port: 443, server_name: null }, target: 'vpn.acme.example:443', agent_id: null, runner_agent_id: 'a-1', runner_hostname: 'acme-dc01', runner_online: true, state: 'up', state_since: ago(60 * 24 * 20), last_at: ago(2), last_ms: 41, last_message: 'certificate valid for 9 more days (TLSv1.3)', last_value: 9, cert_not_after: ago(-60 * 24 * 9 - 60), cert: { subject: 'CN=vpn.acme.example, O=Acme Corp', issuer: 'C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1', sans: ['vpn.acme.example'], not_before: ago(60 * 24 * 356), not_after: ago(-60 * 24 * 9 - 60), untrusted: null }, open_alerts: 1, uptime_24h: 100, uptime_30d: 100 },
	{ ...monitorBase, id: 'um-erp', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-wh', site_name: 'Warehouse', name: 'ERP database', kind: 'tcp', config: { host: '10.20.0.15', port: 1433 }, target: '10.20.0.15:1433', agent_id: 'a-2', runner_agent_id: 'a-2', runner_hostname: 'acme-fs01', runner_online: true, state: 'down', state_since: ago(23), fail_count: 23, last_at: ago(1), last_ms: null, last_message: '10.20.0.15:1433: connection refused', open_alerts: 1, uptime_24h: 98.4, uptime_30d: 99.12 },
	{ ...monitorBase, id: 'um-dns', client_id: 'c-globex', client_name: 'Globex', site_id: 's-globex', site_name: 'Main', name: 'Mail MX record', kind: 'dns', interval_secs: 300, config: { name: 'globex.example', record: 'MX', server: null, expect: ['10 mail.globex.example'] }, target: 'globex.example MX', agent_id: null, runner_agent_id: 'a-5', runner_hostname: 'globex-app01', runner_online: true, state: 'up', state_since: ago(60 * 24 * 80), last_at: ago(3), last_ms: 12, last_message: '10 mail.globex.example', uptime_24h: 100, uptime_30d: 100 },
	{ ...monitorBase, id: 'um-ping', client_id: 'c-initech', client_name: 'Initech', site_id: 's-initech', site_name: 'Main', name: 'Branch router', kind: 'ping', config: { host: '192.168.50.1' }, target: '192.168.50.1', agent_id: null, runner_agent_id: 'a-7', runner_hostname: 'initech-ws-12', runner_online: false, state: 'unknown', state_since: ago(60 * 5), last_at: ago(60 * 5 + 3), last_ms: 3, last_message: 'reply in 3 ms', uptime_24h: 100, uptime_30d: 99.99 }
];
function monitorDetail(m: (typeof uptimeMonitors)[number]) {
	const today = new Date(Date.UTC(NOW.getUTCFullYear(), NOW.getUTCMonth(), NOW.getUTCDate()));
	const days = Array.from({ length: 90 }, (_, i) => {
		const day = new Date(today.getTime() - (89 - i) * 86_400_000).toISOString();
		const checks = i < 12 && m.id !== 'um-web' ? 0 : 1440;
		const failures = m.id === 'um-erp' && i === 89 ? 23 : m.id === 'um-web' && (i === 40 || i === 71) ? (i === 40 ? 4 : 19) : 0;
		return { day, checks, failures, uptime: checks ? Math.round(((checks - failures) * 10000) / checks) / 100 : null };
	}).filter((d) => d.checks);
	const alerts = m.id === 'um-vpn' ? [{ id: 'al-mon-1', title: 'Certificate expires in 9 days: VPN gateway', severity: 'critical', kind: 'uptime', opened_at: ago(60 * 24 * 5), acknowledged_at: null }] : m.id === 'um-erp' ? [{ id: 'al-mon-2', title: 'Monitor down: ERP database', severity: 'critical', kind: 'uptime', opened_at: ago(22), acknowledged_at: null }] : [];
	const recent = Array.from({ length: 8 }, (_, i) => ({ ts: ago(i * (m.interval_secs / 60) + 1), ok: m.state !== 'down', ms: m.state === 'down' ? null : (m.last_ms ?? 20) + ((i * 7) % 5) * 3, message: m.last_message ?? '' }));
	return { ...m, days, alerts, recent };
}
const uptimePoints = (id: string) =>
	Array.from({ length: 96 }, (_, i) => {
		const down = id === 'um-erp' && i >= 94;
		return { ts: new Date(NOW.getTime() - (95 - i) * 15 * 60_000).toISOString(), checks: 15, failures: down ? 15 : 0, avg_ms: down ? null : (id === 'um-web' ? 170 : 40) + ((i * 11) % 9) * 6, max_ms: down ? null : (id === 'um-web' ? 260 : 70) };
	});
const backupJobsMock = [
	{ agent_id: 'a-2', hostname: 'acme-fs01', online: true, client_id: 'c-acme', client_name: 'Acme Corp', site_name: 'Head office', provider: 'veeam', job: 'Nightly file server', last_run_at: ago(60 * 7), last_success_at: ago(60 * 31), last_result: 'failed', message: 'Error: There is not enough space on the disk.', size_bytes: null, updated_at: ago(12), alerting: true },
	{ agent_id: 'a-2', hostname: 'acme-fs01', online: true, client_id: 'c-acme', client_name: 'Acme Corp', site_name: 'Head office', provider: 'wsb', job: 'Windows Server Backup', last_run_at: ago(60 * 6), last_success_at: ago(60 * 6), last_result: 'success', message: '14 versions', size_bytes: null, updated_at: ago(12), alerting: false },
	{ agent_id: 'a-1', hostname: 'acme-dc01', online: true, client_id: 'c-acme', client_name: 'Acme Corp', site_name: 'Head office', provider: 'wsb', job: 'Windows Server Backup', last_run_at: ago(60 * 5), last_success_at: ago(60 * 5), last_result: 'warning', message: 'One of the volumes was skipped.', size_bytes: null, updated_at: ago(20), alerting: false },
	{ agent_id: 'a-6', hostname: 'globex-db01', online: true, client_id: 'c-globex', client_name: 'Globex', site_name: 'Main', provider: 'restic', job: 'sftp:backup@nas.globex.example:/srv/restic/db01', last_run_at: ago(60 * 3), last_success_at: ago(60 * 3), last_result: 'success', message: 'snapshot 5e4f3a2b of /var/lib/postgresql', size_bytes: 52_428_800_000, updated_at: ago(40), alerting: false },
	{ agent_id: 'a-5', hostname: 'globex-app01', online: true, client_id: 'c-globex', client_name: 'Globex', site_name: 'Main', provider: 'file_age', job: '/srv/dumps/*.sql.gz', last_run_at: ago(60 * 50), last_success_at: ago(60 * 50), last_result: 'success', message: 'newest file app-2026-06-13.sql.gz', size_bytes: 734_003_200, updated_at: ago(33), alerting: true }
];

const netDevices = [
	netDev(1, 'Core switch', 'switch', '192.168.10.2', 'up', { sys_descr: 'Cisco IOS Software, Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4', vendor: 'Cisco Systems', mac: '00:1b:54:aa:10:02', cpu_percent: 17, mem_used: 612_000_000, mem_total: 2_000_000_000, interfaces: 8, interfaces_up: 5, storage: [{ descr: 'flash:', kind: 'disk', used: 410_000_000, total: 1_600_000_000 }] }),
	netDev(2, 'Edge firewall', 'firewall', '192.168.10.1', 'down', { sys_descr: 'Fortinet FortiGate-60F v7.4.3', vendor: 'Fortinet', mac: '90:6c:ac:11:22:33', interfaces: 4, interfaces_up: 0 }),
	netDev(3, 'Reception printer', 'printer', '192.168.10.41', 'up', {
		sys_descr: 'HP LaserJet MFP M430f', vendor: 'HP', mac: '3c:2a:f4:5d:0e:91', uptime_secs: 86400 * 3,
		supplies: [{ index: 1, description: 'Black Toner Cartridge', class: 3, kind: 3, percent: 8 }, { index: 2, description: 'Imaging Drum', class: 3, kind: 9, percent: 64 }, { index: 3, description: 'Waste Toner Box', class: 4, kind: 4, percent: 31 }]
	})
];
const netDetail = (d: (typeof netDevices)[number]) => ({
	...d, interfaces: d.id === 'nd-1' ? netPorts : [],
	alerts: d.state === 'down' ? [{ id: 'al-net-1', title: 'Edge firewall isn’t answering SNMP', severity: 'critical', kind: 'net_down', opened_at: ago(46), acknowledged_at: null }] : []
});
const netPoints = (dev: string) =>
	Array.from({ length: 48 }, (_, i) => ({
		ts: new Date(NOW.getTime() - (47 - i) * 30 * 60_000).toISOString(), reachable_pct: dev === 'nd-2' && i > 45 ? 0 : 100, rtt_ms: dev === 'nd-2' && i > 45 ? null : 2 + ((i * 7) % 5),
		cpu_percent: dev === 'nd-1' ? 12 + ((i * 5) % 14) : null, mem_used: dev === 'nd-1' ? 580_000_000 + ((i * 3) % 9) * 6_000_000 : null, mem_total: dev === 'nd-1' ? 2_000_000_000 : null
	}));
const discovered = (n: number, ip: string, name: string, kind: string, state: string, extra: Record<string, unknown> = {}) => ({
	id: `dd-${n}`, site_id: 's-acme-hq', site_name: 'Head office', client_id: 'c-acme', client_name: 'Acme Corp', ip, mac: null as string | null, hostname: null as string | null, mdns_name: null as string | null,
	vendor: null as string | null, sys_name: null as string | null, sys_descr: null as string | null, sys_object_id: null, sys_location: null, credential_id: null as string | null, open_ports: [] as number[],
	methods: ['tcp', 'arp'], kind, status: state === 'unmanaged' || state === 'managed' || state === 'monitored' ? 'unmanaged' : state, note: '', agent_id: null as string | null, agent_hostname: null as string | null,
	net_device_id: null as string | null, online: true, rtt_ms: 2, first_seen_at: ago(60 * 24 * 9), last_seen_at: ago(14), state, name, ...extra
});
const discoveredHosts = [
	discovered(1, '192.168.10.88', 'CAM-LOBBY', 'other', 'unmanaged', { mac: '9c:8e:cd:01:7a:42', vendor: 'Amcrest Technologies', open_ports: [80, 554], first_seen_at: ago(60 * 5) }),
	discovered(2, '192.168.10.130', 'jsmith-laptop', 'windows', 'unmanaged', { mac: 'f8:75:a4:6e:12:09', vendor: 'LCFC(HeFei) Electronics', hostname: 'jsmith-laptop.acme.local', open_ports: [135, 445, 3389], methods: ['icmp', 'tcp', 'arp', 'dns'] }),
	discovered(3, '192.168.10.45', 'switch-2f', 'switch', 'unmanaged', { mac: '24:a4:3c:9b:aa:10', vendor: 'Ubiquiti Inc', sys_name: 'switch-2f', sys_descr: 'UniFi US-24-250W, 6.6.65', credential_id: 'nc-1', open_ports: [22, 80, 443], methods: ['tcp', 'arp', 'snmp'] }),
	discovered(4, '192.168.10.12', 'acme-dc01', 'windows', 'managed', { mac: '00:15:5d:0a:0b:0c', agent_id: 'a-1', agent_hostname: 'acme-dc01', open_ports: [135, 445, 3389] }),
	discovered(5, '192.168.10.2', 'Core switch', 'switch', 'monitored', { net_device_id: 'nd-1', sys_name: 'core-switch', credential_id: 'nc-1', methods: ['tcp', 'snmp'] }),
	discovered(6, '192.168.10.201', 'Label printer', 'printer', 'known', { note: 'Dispatch label printer', open_ports: [9100], vendor: 'Zebra Technologies', mac: '00:07:4d:11:22:33' }),
	discovered(7, '192.168.10.99', 'unknown-99', 'other', 'unmanaged', { online: false, last_seen_at: ago(60 * 30), mac: 'b8:27:eb:12:34:56', vendor: 'Raspberry Pi Foundation' })
];
const netCredentials = [
	{ id: 'nc-1', client_id: 'c-acme', name: 'Switches (read-only)', version: 'v2c', username: '', auth_proto: null, priv_proto: null, context: '', devices: 2, created_at: ago(60 * 24 * 30), updated_at: ago(60 * 24 * 30) },
	{ id: 'nc-2', client_id: 'c-acme', name: 'Firewall (SNMPv3)', version: 'v3', username: 'rmm-monitor', auth_proto: 'sha256', priv_proto: 'aes128', context: '', devices: 1, created_at: ago(60 * 24 * 12), updated_at: ago(60 * 24 * 2) }
];
const siteNetwork = (site: (typeof sites)[number]) => ({
	site_id: site.id, site_name: site.name, client_id: site.client_id, agent_id: site.id === 's-acme-hq' ? 'a-1' : null, agent_hostname: site.id === 's-acme-hq' ? 'acme-dc01' : null,
	agent_online: site.id === 's-acme-hq', agent_capable: site.id === 's-acme-hq', subnets: site.id === 's-acme-hq' ? ['192.168.10.0/24'] : [], discovery_hours: site.id === 's-acme-hq' ? 24 : 0, credential_ids: site.id === 's-acme-hq' ? ['nc-1'] : [],
	poll_secs: 300, candidates: agents.filter((a) => a.site_id === site.id).map((a) => ({ id: a.id, hostname: a.hostname, online: a.online, capable: a.os_family === 'windows' })),
	last_scan: site.id === 's-acme-hq' ? { id: 'sc-n1', status: 'done', subnets: ['192.168.10.0/24'], scanned: 254, found: 31, new_hosts: 2, error: null, requested_by_name: null, created_at: ago(60 * 3), finished_at: ago(60 * 3 - 2) } : null,
	devices: site.id === 's-acme-hq' ? 3 : 0
});

// --- API keys, service accounts and webhooks -----------------------------------------------------
const apiKeys = [
	{ id: 'k-1', name: 'Reporting script', prefix: 'rmm_k_3f9a1c', owner_id: 'u-1', owner_name: 'Dana Admin', service_account: false, access: 'read', scopes: ['clients', 'agents', 'alerts'], permissions: [] as string[], client_ids: null as string[] | null, rate_limit_per_min: 600, expires_at: ago(-60 * 24 * 80), last_used_at: ago(12), last_used_ip: '203.0.113.20', revoked_at: null as string | null, created_at: ago(60 * 24 * 10), status: 'active' },
	{ id: 'k-2', name: 'Ticket sync', prefix: 'rmm_k_b84e07', owner_id: 'u-1', owner_name: 'Dana Admin', service_account: false, access: 'write', scopes: ['tickets', 'jobs'], permissions: [], client_ids: ['c-acme'], rate_limit_per_min: 120, expires_at: null, last_used_at: null, last_used_ip: null, revoked_at: null, created_at: ago(60 * 24 * 2), status: 'active' },
	{ id: 'k-3', name: 'Old exporter', prefix: 'rmm_k_09d2c5', owner_id: 'u-1', owner_name: 'Dana Admin', service_account: false, access: 'read', scopes: ['agents', 'security'], permissions: ['security.read'], client_ids: null, rate_limit_per_min: 600, expires_at: ago(60 * 24 * 3), last_used_at: ago(60 * 24 * 40), last_used_ip: '198.51.100.4', revoked_at: null, created_at: ago(60 * 24 * 120), status: 'expired' }
];
const allApiKeys = [
	...apiKeys,
	{ id: 'k-4', name: 'Backup monitor', prefix: 'rmm_k_71c0aa', owner_id: 'u-sa', owner_name: 'Backup monitor', service_account: true, access: 'read', scopes: ['agents', 'alerts'], permissions: [], client_ids: ['c-globex'], rate_limit_per_min: 300, expires_at: ago(-60 * 24 * 300), last_used_at: ago(3), last_used_ip: '10.0.0.8', revoked_at: null, created_at: ago(60 * 24 * 30), status: 'active' },
	{ id: 'k-5', name: 'Leaked in a gist', prefix: 'rmm_k_5e22f9', owner_id: 'u-2', owner_name: 'Terry Tech', service_account: false, access: 'read', scopes: ['tickets'], permissions: [], client_ids: null, rate_limit_per_min: 600, expires_at: null, last_used_at: ago(60 * 24), last_used_ip: '192.0.2.77', revoked_at: ago(60 * 24 * 2), created_at: ago(60 * 24 * 60), status: 'revoked' }
];
const serviceAccounts = [
	{ id: 'u-sa', name: 'Backup monitor', role: 'readonly', disabled: false, all_clients: false, client_ids: ['c-globex'], keys: 1, created_at: ago(60 * 24 * 30) },
	{ id: 'u-sa2', name: 'Reporting pipeline', role: 'technician', disabled: false, all_clients: true, client_ids: [] as string[], keys: 0, created_at: ago(60 * 24 * 5) }
];
const webhookEvents = ['ticket.created', 'ticket.updated', 'ticket.status_changed', 'ticket.resolved', 'ticket.comment', 'alert.created', 'alert.acknowledged', 'alert.resolved'];
const webhooks = [
	{ id: 'wh-1', name: 'Ticket mirror', url: 'https://hooks.northwind.example/rmm/tickets', client_id: null, client_name: null, events: webhookEvents.slice(0, 5), internal_notes: false, enabled: true, created_at: ago(60 * 24 * 20), pending: 0, failed_24h: 0, last_sent_at: ago(9) },
	{ id: 'wh-2', name: 'Acme dashboard', url: 'https://acme.example/api/rmm-events', client_id: 'c-acme', client_name: 'Acme Corp', events: webhookEvents, internal_notes: true, enabled: true, created_at: ago(60 * 24 * 6), pending: 2, failed_24h: 1, last_sent_at: ago(60 * 5) },
	{ id: 'wh-3', name: 'Chat bridge (paused)', url: 'http://10.0.0.30:8088/hook', client_id: null, client_name: null, events: ['alert.created', 'alert.resolved'], internal_notes: false, enabled: false, created_at: ago(60 * 24 * 40), pending: 0, failed_24h: 0, last_sent_at: null }
];
const webhookDeliveries = [
	{ id: 9, delivery_id: '6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111', event: 'ticket.status_changed', status: 'pending', attempts: 2, response_status: 502, duration_ms: 1840, last_error: 'HTTP 502 Bad Gateway: upstream timed out', created_at: ago(40), sent_at: null, next_attempt_at: ago(-20) },
	{ id: 8, delivery_id: '2c7d9b30-5a0e-4a6f-8a1d-77f5a1b3c9e2', event: 'ticket.comment', status: 'failed', attempts: 5, response_status: null, duration_ms: 15012, last_error: 'request failed: error sending request for url (https://acme.example/api/rmm-events)', created_at: ago(60 * 20), sent_at: null, next_attempt_at: ago(60 * 17) },
	{ id: 7, delivery_id: 'b0a84e2c-91d3-4b57-bf0a-35c2d1e8f640', event: 'alert.created', status: 'sent', attempts: 1, response_status: 200, duration_ms: 118, last_error: null, created_at: ago(60 * 5), sent_at: ago(60 * 5), next_attempt_at: ago(60 * 5) },
	{ id: 6, delivery_id: '91e3f7a2-0c4b-4d18-a6e5-5d2b8c7f1a03', event: 'ticket.created', status: 'sent', attempts: 1, response_status: 204, duration_ms: 87, last_error: null, created_at: ago(60 * 7), sent_at: ago(60 * 7), next_attempt_at: ago(60 * 7) },
	{ id: 5, delivery_id: '5d6a0f19-3e8c-4c72-9b41-e0a7c2d8b6f5', event: 'ping', status: 'sent', attempts: 1, response_status: 200, duration_ms: 64, last_error: null, created_at: ago(60 * 24), sent_at: ago(60 * 24), next_attempt_at: ago(60 * 24) }
];
const siemDestinations = [
	{ id: 'sd-1', name: 'Splunk (HEC)', kind: 'https', address: 'https://splunk.northwind.example:8088/services/collector/event', framing: 'octet', https_format: 'splunk_hec', has_token: true, ca_pem: null, facility: 13, send_audit: true, send_detections: true, send_alerts: true, enabled: true, consecutive_failures: 0, next_attempt_at: ago(1), last_attempt_at: ago(1), last_success_at: ago(1), last_error: null, sent_total: 18432, dropped_total: 0, pending: 0, created_at: ago(60 * 24 * 12) },
	{ id: 'sd-2', name: 'Graylog (TLS)', kind: 'syslog_tls', address: 'logs.northwind.example:6514', framing: 'octet', https_format: 'generic', has_token: false, ca_pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----', facility: 13, send_audit: true, send_detections: false, send_alerts: false, enabled: true, consecutive_failures: 6, next_attempt_at: ago(-9), last_attempt_at: ago(2), last_success_at: ago(60 * 3), last_error: 'TLS handshake: invalid peer certificate: UnknownIssuer', sent_total: 912, dropped_total: 0, pending: 241, created_at: ago(60 * 24 * 4) },
	{ id: 'sd-3', name: 'Lab syslog (paused)', kind: 'syslog_udp', address: '10.0.0.40:514', framing: 'octet', https_format: 'generic', has_token: false, ca_pem: null, facility: 16, send_audit: true, send_detections: false, send_alerts: true, enabled: false, consecutive_failures: 0, next_attempt_at: ago(60 * 24), last_attempt_at: null, last_success_at: null, last_error: null, sent_total: 0, dropped_total: 0, pending: 0, created_at: ago(60 * 24 * 2) }
];
const openapi = {
	openapi: '3.1.0',
	info: { title: 'RMM API', version: '1.0.0', description: 'Authenticate with an API key.' },
	tags: [{ name: 'clients', description: 'Clients and sites' }, { name: 'agents', description: 'Agents, inventory and metrics' }, { name: 'tickets', description: 'Tickets' }],
	paths: {
		'/clients': { get: { operationId: 'listClients', summary: 'List clients with their sites', description: 'Any key that holds the `clients` scope. Only the clients the key can see.', tags: ['clients'], parameters: [], 'x-rmm-scope': 'clients', 'x-rmm-access': 'read' } },
		'/agents': { get: { operationId: 'listAgents', summary: 'List agents (devices)', description: 'Any key that holds the `agents` scope. Search matches hostname, OS, IP address prefix and logged-in user.', tags: ['agents'], parameters: [{ name: 'client_id', in: 'query', description: 'Only this client.', schema: { type: 'string', format: 'uuid' } }, { name: 'online', in: 'query', description: 'Only online or only offline agents.', schema: { type: 'boolean' } }, { name: 'limit', in: 'query', schema: { type: 'integer' } }], 'x-rmm-scope': 'agents', 'x-rmm-access': 'read' } },
		'/agents/{id}': { get: { operationId: 'getAgent', summary: 'Get an agent with its hardware and software inventory', description: 'Any key that holds the `agents` scope.', tags: ['agents'], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], 'x-rmm-scope': 'agents', 'x-rmm-access': 'read' } },
		'/tickets': { post: { operationId: 'createTicket', summary: 'Open a ticket', description: 'A key with `write` access that holds the `tickets` scope.', tags: ['tickets'], parameters: [], requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/NewTicket' } } } }, 'x-rmm-scope': 'tickets', 'x-rmm-access': 'write' } }
	},
	components: { schemas: { NewTicket: { type: 'object', required: ['subject'], properties: { subject: { type: 'string' }, client_id: { type: 'string', format: 'uuid' }, priority: { type: 'integer' } } } } }
};

// White-labelling (branding.rs): a branded instance, and a client (Acme) with its own override.
// The palette is what branding::theme derives for #1d4ed8.
const brandImages: Record<string, Buffer> = Object.fromEntries(
	['logo_light', 'logo_dark', 'icon'].map((v) => [v, readFileSync(new URL(`./fixtures/brand-${v.replace('_', '-')}.png`, import.meta.url))])
);
const brandTheme = {
	light: { accent: '#1d4ed8', accent_hover: '#183fa1', accent_soft: '#e4eafa', on_accent: '#ffffff', accent_ink: '#1d4ed8', cta: '#1d4ed8', cta_hover: '#1b48c2', on_cta: '#ffffff', focus: '#1d4ed8', nav_indicator: '#6183e4' },
	dark: { accent: '#6c8ce6', accent_hover: '#98afee', accent_soft: '#102649', on_accent: '#0c1b21', accent_ink: '#6c8ce6', cta: '#1d4ed8', cta_hover: '#1b48c2', on_cta: '#ffffff', focus: '#6c8ce6', nav_indicator: '#6183e4' }
};
const branding = {
	product_name: 'Northwind Remote',
	name: 'Northwind Remote',
	logo_light: '/api/branding/logo_light?v=1a2b3c4d',
	logo_dark: '/api/branding/logo_dark?v=1a2b3c4d',
	icon: '/api/branding/icon?v=1a2b3c4d',
	accent: '#1d4ed8',
	theme: brandTheme,
	support: { email: 'help@northwind.example', phone: '+1 555 0100', url: 'https://northwind.example/support', hours: 'Mon–Fri 8:00–18:00' },
	source_url: 'https://github.com/ItzLcky/rivvie-rmm'
};
const brandingView = {
	exists: true,
	product_name: 'Northwind Remote',
	accent: '#1d4ed8',
	support_email: 'help@northwind.example',
	support_phone: '+1 555 0100',
	support_url: 'https://northwind.example/support',
	support_hours: 'Mon–Fri 8:00–18:00',
	email_from_name: 'Northwind Help Desk',
	email_footer: 'Northwind IT · 12 Harbour Rd · +1 555 0100',
	logo_light: '/api/settings/branding/logo_light?v=1a2b3c4d',
	logo_dark: '/api/settings/branding/logo_dark?v=1a2b3c4d',
	icon: '/api/settings/branding/icon?v=1a2b3c4d',
	updated_at: ago(60 * 24 * 3),
	resolved: branding
};
const acmeBranding = { ...branding, support: { ...branding.support, email: 'acme-desk@northwind.example', hours: '24/7' } };
const acmeBrandingView = {
	exists: true,
	product_name: null,
	accent: null,
	support_email: 'acme-desk@northwind.example',
	support_phone: null,
	support_url: null,
	support_hours: '24/7',
	email_from_name: 'Northwind for Acme',
	email_footer: null,
	logo_light: null,
	logo_dark: null,
	icon: null,
	updated_at: ago(60 * 24),
	resolved: acmeBranding
};
const portalMe = {
	contact: { id: 'ct-ann', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-hq', name: 'Ann Lopez', email: 'ann@acme.example', is_primary: true, portal_all_tickets: false },
	company_name: 'Northwind IT',
	welcome: 'Tell us what is wrong and we will get back to you.',
	devices: true,
	sees_all_tickets: true,
	invoices: false,
	has_password: true,
	totp_enabled: false,
	attachment_max_mb: 100
};
const portalTickets = [
	{ id: 'pt-1', number: 1042, subject: 'Printer on the second floor jams', status_name: 'In progress', status_category: 'open', priority: 3, contact_name: 'Ann Lopez', created_at: ago(60 * 26), last_activity_at: ago(45), merged_into: null },
	{ id: 'pt-2', number: 1031, subject: 'New starter laptop for Raj', status_name: 'Resolved', status_category: 'resolved', priority: 3, contact_name: 'Ann Lopez', created_at: ago(60 * 24 * 6), last_activity_at: ago(60 * 24 * 2), merged_into: null }
];

export async function mockApi(p: Page, opts: { signedIn?: boolean; ssoRequired?: boolean; branded?: boolean } = {}) {
	const signedIn = opts.signedIn ?? true;
	await p.clock.setFixedTime(NOW);
	await p.route('**/api/**', async (route: Route) => {
		const url = new URL(route.request().url());
		const path = url.pathname.replace(/^\/api/, '');
		// The live stream never answers: the dot shows "connecting" and pages keep their data.
		if (path === '/events') return;
		const q = url.searchParams;
		const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
		if (path === '/security/hunt' && route.request().method() === 'POST') {
			const r = hunt(route.request().postDataJSON() ?? {});
			return json(r.body, r.status);
		}
		if (route.request().method() === 'POST' && /^\/vault\/[^/]+\/reveal$/.test(path)) return json({ value: 'Tr0ub4dor&3-hx9Q' });
		if (route.request().method() === 'POST' && /^\/vault\/[^/]+\/totp$/.test(path)) return json({ code: '492039', digits: 6, period: 30, remaining: 17 });
		if (route.request().method() === 'POST' && path === '/agents/wake')
			return json({ results: [{ agent_id: 'a-5', outcome: 'sent', sender_id: 'a-3' }], sent: 1, no_mac: 0, no_sender: 0, online: 0 });
		if (route.request().method() === 'POST' && /^\/agents\/[^/]+\/wake$/.test(path))
			return json({ results: [{ agent_id: path.split('/')[2], outcome: 'sent', sender_id: 'a-3' }], sent: 1, no_mac: 0, no_sender: 0, online: 0, outcome: 'sent' });
		if (route.request().method() !== 'GET') return json({ ok: true });
		let m: RegExpMatchArray | null;
		if (path === '/settings/public') return json({ company_name: 'Northwind IT', ...(opts.branded ? { branding } : {}) });
		if ((m = path.match(/^\/(?:portal\/|settings\/|clients\/[^/]+\/)?branding\/(logo_light|logo_dark|icon)$/)) && brandImages[m[1]]) {
			return route.fulfill({ status: 200, contentType: 'image/png', body: brandImages[m[1]] });
		}
		if (path === '/settings/branding') return json(brandingView);
		if (path === '/clients/c-acme/branding') return json(acmeBrandingView);
		if (path === '/portal/info') return json({ company_name: 'Northwind IT', welcome: portalMe.welcome, ...(opts.branded ? { branding } : {}) });
		if (path === '/portal/me') return json({ ...portalMe, ...(opts.branded ? { branding: acmeBranding } : {}) });
		if (path === '/portal/tickets') return json(portalTickets);
		if (path === '/auth/me') return signedIn ? json(admin) : json({ error: 'not authenticated' }, 401);
		if (path === '/dashboard') return json(dashboard(q.get('client_id')));
		if (path === '/clients') return json(clients.map(clientOut));
		if ((m = path.match(/^\/clients\/([^/]+)$/))) return json(clientOut(clients.find((c) => c.id === m![1])!));
		if ((m = path.match(/^\/clients\/([^/]+)\/docs$/))) return json(clientDocs.filter((d) => d.client_id === m![1]).map(docRow));
		if ((m = path.match(/^\/docs\/([^/]+)$/))) {
			const d = clientDocs.find((x) => x.id === m![1]);
			return d ? json(docDetail(d)) : json({ error: 'document not found' }, 404);
		}
		if (path === '/doc-categories') return json(docCategories.map(categoryOut));
		if (path === '/doc-templates') return json(docTemplates);
		if ((m = path.match(/^\/doc-templates\/([^/]+)$/))) return json({ ...docTemplates.find((t) => t.id === m![1])!, body: '# {{client.name}}\n\n```fields\nLabel:\n```\n' });
		if ((m = path.match(/^\/clients\/([^/]+)\/vault$/))) {
			const kind = url.searchParams.get('kind');
			return json(vaultItems.filter((v) => v.client_id === m![1] && (!kind || (kind === 'manual' ? !v.managed_kind : kind === 'managed' ? !!v.managed_kind : v.managed_kind === kind))));
		}
		if ((m = path.match(/^\/vault\/([^/]+)$/))) return json(vaultDetail(m![1]));
		if (path === '/tags') return json(tagsOut());
		if (path === '/custom-fields') return json(fieldDefs.filter((f) => !q.get('entity') || f.entity === q.get('entity')));
		if ((m = path.match(/^\/(agents|clients|sites)\/([^/]+)\/fields$/))) return json(fieldValues(m[1].slice(0, -1)).filter((f) => m![1] !== 'agents' || f.client_id !== 'c-acme' || m![2] === 'a-1' || m![2] === 'a-2' || m![2] === 'a-3'));
		if ((m = path.match(/^\/agents\/([^/]+)\/notes$/))) return json(notes.filter((n) => n.agent_id === m![1]));
		if (path === '/saved-views') return json(savedViews);
		if (path === '/agents') {
			let list = agents.filter((a) => (!q.get('client_id') || a.client_id === q.get('client_id')) && (!q.get('online') || String(a.online) === q.get('online')));
			if (q.get('health')) list = list.filter((a) => q.get('health')!.split(',').includes(a.health));
			if (q.get('new_days')) list = list.filter((a) => Date.parse(a.enrolled_at) > NOW.getTime() - Number(q.get('new_days')) * 86_400_000);
			if (q.get('os')) list = list.filter((a) => a.os_family === q.get('os'));
			if (q.get('category_id')) list = list.filter((a) => a.category_id === q.get('category_id'));
			if (q.get('policy_set_id')) list = list.filter((a) => a.policy_set_id === q.get('policy_set_id'));
			if (q.get('q')) list = list.filter((a) => a.hostname.includes(q.get('q')!));
			if (q.get('tag')) list = list.filter((a) => q.get('tag')!.split(',').every((t) => a.tags.some((x) => x.id === t)));
			return json(page(list, Number(q.get('limit') ?? 50)));
		}
		if ((m = path.match(/^\/agents\/([^/]+)$/))) return json(detail(agents.find((a) => a.id === m![1])!));
		if ((m = path.match(/^\/agents\/([^/]+)\/metrics$/))) return json(metricHistory(agents.find((a) => a.id === m![1])!));
		if (path.match(/^\/agents\/[^/]+\/activity$/)) return json([{ id: 1, ts: ago(300), user_name: 'Dana Admin', action: 'agent.update_offer', target_type: 'agent', target_id: 'a-1', details: { version: '0.4.2' } }, { id: 2, ts: ago(290), user_name: null, action: 'agent.update_completed', target_type: 'agent', target_id: 'a-1', details: { version: '0.4.2' } }]);
		if ((m = path.match(/^\/agents\/([^/]+)\/patches$/))) return json(agentPatches(agents.find((a) => a.id === m![1])!));
		if ((m = path.match(/^\/agents\/([^/]+)\/security$/))) {
			return json(agentSecurity(agents.find((x) => x.id === m![1])!));
		}
		if ((m = path.match(/^\/agents\/([^/]+)\/telemetry$/))) {
			const a = agents.find((x) => x.id === m![1])!;
			if (!a.online) return json({ error: 'the agent is offline' }, 409);
			return json({ events: q.get('around') ? telemetryEvents : telemetryEvents.slice(0, 5), truncated: false, error: null });
		}
		if ((m = path.match(/^\/security\/detections\/([^/]+)$/))) return json(detectionDetail(m![1]));
		if (path === '/security/quarantine') {
			const t = q.get('q')?.toLowerCase();
			return json(quarantine.filter((x) => (q.get('state') === 'all' || x.state === 'quarantined') && (!q.get('client_id') || x.client_id === q.get('client_id')) && (!t || `${x.path} ${x.hostname} ${x.sha256}`.toLowerCase().includes(t))));
		}
		if (path === '/security/prevalence') {
			const beacon = q.get('sha256') === HASH_BEACON;
			const agents = beacon ? detectionDetail('d-6').prevalence.concat([{ agent_id: 'a-2', hostname: 'acme-fs01', client_name: 'Acme Corp', first_seen: ago(26), how: 'ran, detected, quarantined', path: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\upd4412.exe' }]) : [];
			return json({ sha256: q.get('sha256'), agents, seen_on: agents.length, first_seen: beacon ? ago(60 * 3) : null, known: beacon ? [{ name: 'CobaltStrike.Beacon', severity: 'severe', source: `db:2026.06.15.1`, added_at: ago(80) }] : [] });
		}
		if (path === '/security/databases') return json({ versions: signatureDatabases, soak_minutes: 1440, verifies_signatures: false });
		if (path === '/security/reputation') return json({ sources: reputationSources });
		if (path === '/security/reputation/rare') {
			const max = Number(q.get('max_agents') ?? 1);
			const client = q.get('client_id') ? clients.find((c) => c.id === q.get('client_id'))?.name : null;
			return json({ items: rarePrograms.filter((r) => r.seen_on <= max && (!client || r.agents.some((a) => a.client_name === client))) });
		}
		if (path === '/security/rules') return json(rules);
		if (path === '/security/content') return json({ versions: contentVersions, canary_clients: 1, soak_minutes: 1440, verifies_signatures: false });
		if (path === '/security/exclusions') return json(exclusions);
		if (path === '/security/summary') return json(securitySummary(q.get('client_id')));
		if (path === '/security/agents') {
			const rank = ['threats', 'unprotected', 'at_risk', 'unknown', 'protected'];
			let list = agents.filter((a) => !q.get('client_id') || a.client_id === q.get('client_id')).map(securityRow).sort((x, y) => rank.indexOf(x.state) - rank.indexOf(y.state));
			if (q.get('state')) list = list.filter((r) => q.get('state')!.split(',').includes(r.state));
			return json(page(list, Number(q.get('limit') ?? 50)));
		}
		if (path === '/security/detections') {
			const all = q.get('view') === 'all';
			return json(
				page(
					allDetections.filter(
						(d) =>
							(all || (d.status === 'active' && !d.resolved_at)) && (!q.get('client_id') || d.client_id === q.get('client_id')) &&
							(q.get('audit') === 'true' || !d.audit) && (!q.get('source') || d.source === q.get('source'))
					),
					Number(q.get('limit') ?? 50)
				)
			);
		}
		if ((m = path.match(/^\/agents\/([^/]+)\/software$/))) return json(agentSoftware(agents.find((a) => a.id === m![1])!));
		if (path === '/software/packages') {
			const t = q.get('q')?.toLowerCase();
			return json(swPackages.filter((p) => (!t || `${p.name} ${p.publisher ?? ''} ${p.winget_id ?? ''}`.toLowerCase().includes(t)) && (!q.get('platform') || p.platforms.includes(q.get('platform')!))));
		}
		if ((m = path.match(/^\/software\/packages\/([^/]+)$/))) return json(swPackages.find((p) => p.id === m![1])!);
		if ((m = path.match(/^\/software\/packages\/([^/]+)\/devices$/))) return json({ items: swDevices.filter((d) => d.package_id === m![1] && (q.get('show') === 'all' || d.installed || d.desired) && (q.get('show') !== 'noncompliant' || d.compliant === false)) });
		if (path === '/software/updates') {
			const items = swDevices.filter((d) => d.installed && d.available && d.ignored !== d.available && (!q.get('client_id') || d.client_id === q.get('client_id')));
			return json({ items, packages: [...new Set(items.map((d) => d.package_id))].map((id) => ({ package_id: id, name: swPackages.find((p) => p.id === id)!.name, devices: items.filter((d) => d.package_id === id).length })) });
		}
		if (path === '/software/runs') return json(swRuns.filter((r) => (!q.get('status') || q.get('status')!.split(',').includes(r.status)) && (!q.get('client_id') || r.client_id === q.get('client_id'))).map(({ output, ...r }) => r));
		if ((m = path.match(/^\/software\/runs\/([^/]+)$/))) return json(swRuns.find((r) => r.id === m![1])!);
		if (path === '/patches') {
			let list = updateGroups();
			if (q.get('client_id')) list = list.filter((u) => updates.find((x) => x.update_id === u.update_id)!.on.some((id) => agents.find((a) => a.id === id)!.client_id === q.get('client_id')));
			if (q.get('approval')) list = list.filter((u) => (u as unknown as Record<string, number>)[q.get('approval')!] > 0);
			return json({ items: list, total: list.length, truncated: false });
		}
		if (path === '/patches/agents') {
			const u = updates.find((x) => x.update_id === q.get('update_id'))!;
			return json([...u.on, ...u.installedOn].map((id) => {
				const a = agents.find((x) => x.id === id)!;
				return { agent_id: a.id, hostname: a.hostname, online: a.online, os_family: a.os_family, client_id: a.client_id, client_name: a.client_name, site_name: a.site_name,
					state: stateOf(u, a.id), approval: approvalOf(u, a.id), approval_manual: u.category === 'driver', approved_by_name: 'Dana Admin', approved_at: ago(600),
					version: null, current_version: null, first_seen_at: ago(60 * 24 * 3), installed_at: u.installedOn.includes(a.id) ? ago(60 * 20) : null, last_error: null, fail_count: 0 };
			}));
		}
		if (path === '/patches/compliance') return json(compliance(q.get('client_id')));
		if (path === '/patch-windows') return json(sites.map(windowRow));
		if (path === '/patch-runs') return json(runs.filter((r) => (!q.get('agent_id') || r.agent_id === q.get('agent_id')) && (!q.get('status') || q.get('status')!.split(',').flatMap((s) => (s === 'active' ? ['queued', 'sent'] : [s])).includes(r.status))));
		if ((m = path.match(/^\/patch-runs\/([^/]+)$/))) {
			const r = runs.find((x) => x.id === m![1])!;
			const items = updates.filter((u) => u.on.includes(r.agent_id) || u.installedOn.includes(r.agent_id)).slice(0, r.updates).map((u, i) => ({ update_id: u.update_id, title: u.title, kb: u.kb, severity: u.severity, ok: r.status === 'sent' ? null : i < r.succeeded, message: r.status !== 'sent' && i >= r.succeeded ? 'install failed (0x80240022)' : null }));
			return json({ ...r, items, output: r.status === 'sent' ? '' : 'installing 2 updates through the Windows Update Agent\nb3c1d2e4-0001: installed\nb3c1d2e4-0002: installed\n' });
		}
		if (path === '/agent-updates') return json({ releases: [], auto_update: false });
		if (path === '/agent-downloads') return json([{ id: 'linux-x86_64', label: 'Linux x86_64', file_name: 'rmm-agent', size: 6_400_000, sha256: 'ab'.repeat(32), url: '#' }]);
		if (path === '/jobs') {
			const st = q.get('status')?.split(',');
			return json(page(jobs.filter((j) => (!q.get('agent_id') || j.agent_id === q.get('agent_id')) && (!q.get('schedule_id') || j.schedule_id === q.get('schedule_id')) && (!st || st.includes(j.status))), Number(q.get('limit') ?? 50)));
		}
		if ((m = path.match(/^\/jobs\/([^/]+)$/))) return json(jobDetail(jobs.find((j) => j.id === m![1])!));
		if (path === '/scripts') return json(scripts);
		if ((m = path.match(/^\/scripts\/([^/]+)$/))) return json(scripts.find((s) => s.id === m![1]));
		if (path === '/audit') return json(page(Array.from({ length: 8 }, (_, i) => ({ id: 100 - i, ts: ago(i * 53), user_name: i % 4 ? 'Dana Admin' : null, action: ['client.create', 'job.create', 'script.update', 'agent.update_offer', 'auth.login', 'site.rename', 'user.create', 'settings.update'][i], target_type: ['client', 'script', 'script', 'agent', null, 'site', 'user', null][i], target_id: i % 2 ? 'x' : null, details: i % 3 ? { name: 'Acme Corp' } : {} }))));
		if (path === '/users')
			return json(
				[
					{ ...admin, permissions: null },
					{ ...admin, id: 'u-2', email: 'terry@northwind.example', name: 'Terry Tech', role: 'technician', totp_enabled: false, client_ids: ['c-acme'], permissions: null },
					{ ...admin, id: 'u-3', email: 'sam@northwind.example', name: 'Sam Security', role: 'readonly', totp_enabled: true, client_ids: null, permissions: ['security.read', 'security.respond', 'security.manage'] }
				].map((u, i) => ({
					...u, disabled: false, last_login_at: ago(60), all_clients: u.role === 'admin' || u.client_ids === null, client_ids: u.client_ids ?? [],
					sso_exempt: i === 0, sso_only: i === 1, passkeys: i === 2 ? 1 : 0, sso_providers: i === 1 ? ['Microsoft'] : []
				}))
			);
		if (path === '/settings') return json({ company_name: 'Northwind IT', session_idle_hours: null, session_idle_hours_default: 12, require_2fa_all: false });
		if (path === '/auth/totp') return json({ enabled: true, required: true, recovery_codes_left: 8 });
		if (path === '/auth/passkeys')
			return json({
				available: true,
				recovery_codes_left: 10,
				sso_only: false,
				passkeys: [
					{ id: 'pk-1', name: 'YubiKey 5C', created_at: ago(60 * 24 * 30), last_used_at: ago(60 * 5) },
					{ id: 'pk-2', name: 'Work laptop', created_at: ago(60 * 24 * 3), last_used_at: null }
				]
			});
		if (path === '/auth/sso/providers')
			return json({ providers: [{ id: 'sso-entra', name: 'Microsoft', preset: 'entra' }, { id: 'sso-google', name: 'Google', preset: 'google' }], sso_required: opts.ssoRequired ?? false });
		if (path === '/settings/sso')
			return json({
				redirect_uri: 'https://rmm.northwind.example/api/auth/sso/callback',
				sso_required: false,
				break_glass: [{ id: 'u-1', email: 'dana@northwind.example', name: 'Dana Admin' }],
				providers: [
					{
						id: 'sso-entra', name: 'Microsoft', preset: 'entra', issuer: 'https://login.microsoftonline.com/6b1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111/v2.0',
						client_id: '3f2a1c9e-77aa-4c2c-9d1e-5b0e8c4d2a10', has_secret: true, scopes: 'openid email profile', enabled: true, groups_claim: 'groups', jit: true,
						group_sync: true, default_role: null, allowed_domains: ['northwind.example'], allowed_tenants: [], trust_email: true, identities: 6,
						maps: [
							{ group_value: '0b8d1f64-2e7a-4a53-9c1b-6f1d3a7e9c02', role: 'admin', extra_permissions: [], all_clients: true, client_ids: [] },
							{ group_value: '7c2e5a90-1b44-4d8e-a3f6-2d9b8e4c1f33', role: 'technician', extra_permissions: ['billing.read'], all_clients: false, client_ids: ['c-acme'] }
						]
					},
					{
						id: 'sso-google', name: 'Google', preset: 'google', issuer: 'https://accounts.google.com', client_id: '812345678901-abc.apps.googleusercontent.com',
						has_secret: true, scopes: 'openid email profile', enabled: false, groups_claim: 'groups', jit: false, group_sync: false, default_role: null,
						allowed_domains: [], allowed_tenants: [], trust_email: false, identities: 0, maps: []
					}
				]
			});
		if (path === '/auth/sessions') return json([{ id: 'x1', created_at: ago(600), last_seen_at: ago(0), expires_at: ago(-6000), user_agent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0', current: true }]);
		if (path.match(/^\/sites\/[^/]+\/enrollment-tokens$/)) return json([{ id: 't1', label: 'Office rollout', max_uses: 50, uses: 12, expires_at: ago(-60 * 24 * 20), created_at: ago(60 * 24 * 10), category_id: null, category_name: null }, { id: 't2', label: 'Warehouse tills', max_uses: null, uses: 3, expires_at: null, created_at: ago(60 * 24 * 4), category_id: 'cat-kiosk', category_name: 'Kiosks' }]);
		if (path === '/alerts/summary') return json(alertSummary(q.get('client_id')));
		if (path === '/alerts') {
			const st = q.get('state') ?? 'active';
			const list = alerts.filter(
				(a) =>
					(st === 'all' || (st === 'active' ? a.state !== 'resolved' : a.state === st)) &&
					(!q.get('agent_id') || a.agent_id === q.get('agent_id')) && (!q.get('client_id') || a.client_id === q.get('client_id')) &&
					(!q.get('policy_id') || a.policy_id === q.get('policy_id'))
			);
			return json(page(list, Number(q.get('limit') ?? 50)));
		}
		if ((m = path.match(/^\/alerts\/([^/]+)$/))) {
			const a = alerts.find((x) => x.id === m![1])!;
			return json({ ...a, notifications: deliveries.filter((d) => d.alert_id === a.id).map(({ channel_id, alert_id, alert_title, hostname, next_attempt_at, ...d }) => ({ ...d, channel_kind: channels.find((c) => c.id === channel_id)!.kind })), log_events: [] });
		}
		if (path === '/alert-mutes') {
			const list = mutes.filter((x) => (!q.get('client_id') || x.owner_client_id === q.get('client_id')) && (!q.get('agent_id') || x.agent_id === q.get('agent_id') || x.site_id === agents.find((a) => a.id === q.get('agent_id'))?.site_id));
			return json(list);
		}
		if ((m = path.match(/^\/agents\/([^/]+)\/processes$/))) return json({ processes });
		if ((m = path.match(/^\/agents\/([^/]+)\/files$/))) return json(listing(q.get('path') ?? ''));
		if (path === '/notification-channels') return json(channels);
		if (path === '/oncall/now') return json(oncallSchedules.map((s) => s.now));
		if (path === '/oncall/schedules') return json(oncallSchedules);
		if ((m = path.match(/^\/oncall\/schedules\/([^/]+)\/shifts$/))) return json(m[1] === 'os-1' ? oncallShifts : { ...oncallShifts, layers: [], overrides: [], final: [] });
		if (path === '/oncall/people') return json(oncallPeople);
		if (path === '/oncall/escalation-policies') return json(escalationPolicies);
		if (path === '/oncall/settings') return json({ p1_escalation_policy_id: 'ep-servers' });
		if (path === '/oncall/pages') return json(oncallPages.filter((p) => !q.get('alert_id') || p.alert_id === q.get('alert_id')));
		if (path === '/settings/sms') return json({ account_sid: 'AC5f1e0c2b9d', from: '+15005550006', base_url: 'https://api.twilio.com', token_set: true });
		if (path === '/account/contact-methods') return json({ phone: '+447700900123', phone_verified: true, sms_available: true, devices: 1, rules: [{ method: 'push', delay_minutes: 0 }, { method: 'sms', delay_minutes: 5 }] });
		if (path === '/account/notification-prefs') return json(notificationPrefs);
		if (path === '/push/subscriptions') return json([]);
		if (path === '/notifications') return json(deliveries);
		if (path === '/settings/smtp') return json({ host: 'smtp.office365.com', port: 587, security: 'starttls', username: 'rmm@northwind.example', password_set: true, from: 'Northwind RMM <rmm@northwind.example>' });
		if (path === '/api-keys') return json(q.get('all') ? allApiKeys : apiKeys);
		if (path === '/api-keys/options') return json({ groups: [{ id: 'clients', label: 'Clients and sites' }, { id: 'agents', label: 'Agents, inventory and metrics' }, { id: 'jobs', label: 'Jobs and results' }, { id: 'scripts', label: 'Script library' }, { id: 'alerts', label: 'Alerts' }, { id: 'tickets', label: 'Tickets' }, { id: 'security', label: 'Endpoint protection (needs the security.read permission)' }], permissions: admin.permissions, can_write: true, default_rate_limit: 600 });
		if (path === '/uptime/summary') {
			const ms = uptimeMonitors.filter((m) => !q.get('client_id') || m.client_id === q.get('client_id'));
			return json({ monitors: ms.length, up: ms.filter((m) => m.state === 'up').length, down: ms.filter((m) => m.state === 'down').length, unknown: ms.filter((m) => m.state === 'unknown').length, disabled: 0, uptime_30d: 99.71 });
		}
		if (path === '/uptime/monitors') return json(uptimeMonitors.filter((m) => (!q.get('client_id') || m.client_id === q.get('client_id')) && (!q.get('state') || m.state === q.get('state')) && (!q.get('kind') || m.kind === q.get('kind'))));
		if ((m = path.match(/^\/uptime\/monitors\/([^/]+)\/results$/))) return json(uptimePoints(m[1]));
		if ((m = path.match(/^\/uptime\/monitors\/([^/]+)$/))) {
			const mon = uptimeMonitors.find((x) => x.id === m![1]);
			return mon ? json(monitorDetail(mon)) : json({ error: 'monitor not found' }, 404);
		}
		if (path === '/backups') {
			const rank: Record<string, number> = { failed: 0, warning: 1, unknown: 2, running: 3, success: 4 };
			const rows = backupJobsMock.filter((j) => (!q.get('client_id') || j.client_id === q.get('client_id')) && (!q.get('result') || q.get('result')!.split(',').includes(j.last_result)) && (!q.get('alerting') || j.alerting));
			return json(page([...rows].sort((a, b) => rank[a.last_result] - rank[b.last_result]), Number(q.get('limit') ?? 50)));
		}
		if ((m = path.match(/^\/agents\/([^/]+)\/backups$/))) return json(backupJobsMock.filter((j) => j.agent_id === m![1]));
		if (path === '/network/summary') return json({ unmanaged: discoveredHosts.filter((d) => d.state === 'unmanaged' && d.online).length, devices: netDevices.length, down: netDevices.filter((d) => d.state === 'down').length });
		if (path === '/network/devices')
			return json(netDevices.filter((d) => (!q.get('state') || d.state === q.get('state')) && (!q.get('kind') || d.kind === q.get('kind')) && (!q.get('client_id') || d.client_id === q.get('client_id'))));
		if ((m = path.match(/^\/network\/devices\/([^/]+)\/metrics$/))) return json(netPoints(m[1]));
		if ((m = path.match(/^\/network\/devices\/([^/]+)\/interfaces\/(\d+)\/metrics$/)))
			return json(Array.from({ length: 48 }, (_, i) => ({ ts: new Date(NOW.getTime() - (47 - i) * 30 * 60_000).toISOString(), in_bps: 90_000_000 + ((i * 13) % 17) * 6_000_000, out_bps: 40_000_000 + ((i * 7) % 11) * 5_000_000, util_pct: 14, up_pct: 100 })));
		if ((m = path.match(/^\/network\/devices\/([^/]+)$/))) return json(netDetail(netDevices.find((d) => d.id === m![1])!));
		if (path === '/network/discovered') {
			const st = q.get('state') ?? 'unmanaged';
			return json(discoveredHosts.filter((d) => (st === 'all' || d.state === st) && (!q.get('client_id') || d.client_id === q.get('client_id'))));
		}
		if ((m = path.match(/^\/clients\/([^/]+)\/network-credentials$/))) return json(netCredentials.filter((c) => c.client_id === m![1]));
		if ((m = path.match(/^\/sites\/([^/]+)\/network$/))) return json(siteNetwork(sites.find((x) => x.id === m![1])!));
		if (path === '/service-accounts') return json(serviceAccounts);
		if (path === '/siem/destinations') return json({ destinations: siemDestinations, retain_days: 7 });
		if (path === '/webhooks') return json({ webhooks, events: webhookEvents });
		if ((m = path.match(/^\/webhooks\/([^/]+)\/deliveries$/))) return json(q.get('status') ? webhookDeliveries.filter((d) => d.status === q.get('status')) : webhookDeliveries);
		if (path === '/openapi.json') return json(openapi);
		const pr = policyRoute(path, q);
		if (pr !== undefined) return pr === null ? json({ error: 'policy set not found' }, 404) : json(pr);
		if (path === '/schedules') return json(schedules.map(scheduleOut));
		if (path === '/schedules/preview') return json({ runs: [1, 2, 3, 4, 5].map((d) => new Date(Date.UTC(2026, 5, 15 + d, 2, 0)).toISOString()) });
		if ((m = path.match(/^\/schedules\/([^/]+)$/))) return json(scheduleOut(schedules.find((x) => x.id === m![1])!));
		if (path.match(/^\/agents\/[^/]+\/services$/)) return json({ services, services_at: ago(3), alerting: ['nginx.service'] });
		if (path.match(/^\/agents\/[^/]+\/log-events$/)) return json(logEvents);
		if (path === '/tickets/summary') return json({ open: 4, mine: 1, unassigned: 2, triage: 1, waiting: 1, team: 0, breached: 0 });
		if (path === '/tickets/meta') return json({ boards, types: ticketTypes, technicians: [{ id: 'u-1', name: 'Dana Admin', email: admin.email, client_ids: null }, { id: 'u-2', name: 'Terry Tech', email: 'terry@northwind.example', client_ids: ['c-acme', 'c-globex'] }], teams: [] });
		if (path === '/tickets') return json(page(ticketList(q), Number(q.get('limit') ?? 50)));
		if ((m = path.match(/^\/tickets\/([^/]+)$/))) return json(ticketDetail(tickets.find((t) => t.id === m![1])!));
		if (path === '/report-schedules') return json(reportSchedules);
		if ((m = path.match(/^\/report-schedules\/([^/]+)\/runs$/))) return json(reportRuns.filter((r) => r.schedule_id === m![1]));
		if ((m = path.match(/^\/report-schedules\/([^/]+)$/))) return json(reportSchedules.find((r) => r.id === m![1]));
		if (path === '/contacts') return json(contacts.filter((c) => !q.get('client_id') || c.client_id === q.get('client_id')));
		if (path === '/boards') return json(boards);
		if (path === '/mailboxes') return json(mailboxes);
		if (path === '/mailboxes/inbound') return json(inboundMail);
		if (path === '/search') return json({ agents: agents.filter((a) => a.hostname.includes(q.get('q') ?? '')).slice(0, 5).map((a) => ({ id: a.id, hostname: a.hostname, os_family: a.os_family, online: a.online, client_name: a.client_name, site_name: a.site_name })), clients: [], sites: [], scripts: [], tickets: [] });
		if (path === '/canned-responses' || path === '/teams' || path === '/charges' || path === '/products' || path === '/sla/policies') return json([]);
		if (path === '/sla/calendars') return json([{ id: 'cal-office', name: 'Office hours', timezone: 'Europe/London', hours: [] }]);
		if (path === '/time/timer') return json(null);
		if (path === '/work-types')
			return json([
				{ id: 'wt-1', name: 'Remote support', rate: null, billable: true, active: true, position: 0 },
				{ id: 'wt-2', name: 'Onsite', rate: null, billable: true, active: true, position: 1 }
			]);
		if (path === '/time')
			return json(
				q.get('ticket_id') === 't-1'
					? [
							{
								id: 'te-1', user_id: 'u-1', user_name: 'Dana Admin', client_id: 'c-acme', client_name: 'Acme Corp', ticket_id: 't-1', ticket_number: 10401,
								ticket_subject: 'Printer on the second floor prints blank pages', project_id: null, project_name: null, work_type_id: 'wt-1',
								work_type_name: 'Remote support', started_at: ago(240), ended_at: ago(215), minutes: 25, billable: true, note: 'Restarted the spooler.',
								coverage: null, contract_name: null, rate: null, amount: null, invoiced: false, week_start: '2026-06-15', week_status: 'open'
							}
						]
					: []
			);
		return json({ error: `no mock for ${path}` }, 404);
	});
}
