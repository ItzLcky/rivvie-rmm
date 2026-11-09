/**
 * A mocked API for the visual tests: a small fleet with fixed data and timestamps relative to
 * NOW (the page clock is frozen there), so every screenshot is the same on every run.
 */
import type { Page, Route } from '@playwright/test';

export const NOW = new Date('2026-06-15T14:30:00Z');
const ago = (mins: number) => new Date(NOW.getTime() - mins * 60_000).toISOString();

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
		health, disk_max_pct: health === 'unknown' ? 0 : disk, failed_jobs_24h: failed, open_alerts: 0
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

// --- monitoring -----------------------------------------------------------------------------
const policies = [
	{ id: 'p-off', name: 'Servers offline', kind: 'offline', params: { minutes: 10 }, severity: 'critical', client_id: null, client_name: null, site_id: null, site_name: null, os_family: null, channel_ids: ['ch-mail', 'ch-teams'], notify_resolved: true, enabled: true, open_alerts: 1 },
	{ id: 'p-disk', name: 'Disk nearly full', kind: 'disk', params: { threshold: 90, minutes: 5 }, severity: 'critical', client_id: null, client_name: null, site_id: null, site_name: null, os_family: null, channel_ids: ['ch-mail'], notify_resolved: true, enabled: true, open_alerts: 2 },
	{ id: 'p-cpu', name: 'High CPU', kind: 'cpu', params: { threshold: 85, minutes: 15 }, severity: 'warning', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-hq', site_name: 'Head office', os_family: null, channel_ids: [], notify_resolved: false, enabled: true, open_alerts: 0 },
	{ id: 'p-svc', name: 'Core services', kind: 'service', params: { services: ['nginx', 'Spooler'], auto_only: true, exclude: ['sppsvc'] }, severity: 'warning', client_id: null, client_name: null, site_id: null, site_name: null, os_family: null, channel_ids: ['ch-slack'], notify_resolved: true, enabled: true, open_alerts: 1 },
	{ id: 'p-job', name: 'Backup script fails', kind: 'job_failed', params: { script_id: 's-disk' }, severity: 'warning', client_id: null, client_name: null, site_id: null, site_name: null, os_family: 'linux', channel_ids: ['ch-hook'], notify_resolved: true, enabled: true, open_alerts: 1 },
	{ id: 'p-log', name: 'Kernel OOM killer', kind: 'log', params: { min_level: 'error', sources: ['kernel'], channels: [], event_ids: [], pattern: 'out of memory' }, severity: 'info', client_id: 'c-globex', client_name: 'Globex', site_id: null, site_name: null, os_family: 'linux', channel_ids: [], notify_resolved: true, enabled: false, open_alerts: 0 }
].map((p, i) => ({ ...p, created_at: ago(60 * 24 * (30 - i)), updated_at: ago(60 * (20 - i)) }));
const pol = (id: string) => policies.find((p) => p.id === id)!;
function alert(i: number, policyId: string, agentIdx: number, title: string, opened: number, extra: Record<string, unknown> = {}) {
	const a = agents[agentIdx];
	const p = pol(policyId);
	return {
		id: `al-${i}`, policy_id: p.id, policy_name: p.name, agent_id: a.id, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name, site_name: a.site_name,
		kind: p.kind, severity: p.severity, title, details: {}, occurrences: 1, state: 'open', opened_at: ago(opened), last_seen_at: ago(1),
		acknowledged_at: null, acknowledged_by_name: null, resolved_at: null, resolved_by_name: null, resolution: null, ...extra
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
	{ id: 'ch-hook', name: 'PSA webhook', kind: 'webhook', enabled: false, policies: 1, has_secret: true, config: { url: 'https://psa.northwind.example/hooks/rmm' } }
].map((c, i) => ({ ...c, created_at: ago(60 * 24 * (20 - i)) }));
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
	{ id: 'sc-1', name: 'Nightly disk report', script_id: 's-disk', script_name: 'Disk usage report', interpreter: 'bash', client_id: null, client_name: null, site_id: null, site_name: null, os_family: 'linux', cron: '0 2 * * *', timezone: 'Europe/London', args: [], timeout_secs: null, retain_days: 30, enabled: true, next_run_at: ago(-60 * 11 - 30), last_run_at: ago(60 * 12 + 30), last_run: { succeeded: 3, failed: 1 } },
	{ id: 'sc-2', name: 'Clear print queue', script_id: 's-spool', script_name: 'Restart print spooler', interpreter: 'powershell', client_id: 'c-acme', client_name: 'Acme Corp', site_id: 's-acme-wh', site_name: 'Warehouse', os_family: 'windows', cron: '30 6 * * 1-5', timezone: 'America/Chicago', args: [], timeout_secs: 120, retain_days: 7, enabled: true, next_run_at: ago(-60 * 21), last_run_at: ago(60 * 3), last_run: { succeeded: 1, queued: 1 } },
	{ id: 'sc-3', name: 'Weekly update check', script_id: 's-upd', script_name: 'Pending updates', interpreter: 'python', client_id: null, client_name: null, site_id: null, site_name: null, os_family: null, cron: '0 3 * * 0', timezone: 'UTC', args: ['--security'], timeout_secs: 600, retain_days: 90, enabled: false, next_run_at: ago(-60 * 24 * 3), last_run_at: null, last_run: {} }
].map((s, i) => ({ ...s, created_by_name: 'Dana Admin', created_at: ago(60 * 24 * (40 - i)), updated_at: ago(60 * 24 * (5 - i)) }));
const detail = (a: Agent) => ({
	...a,
	kernel_version: a.os_family === 'windows' ? '10.0.20348' : '6.8.0-45-generic',
	machine_id: 'm-' + a.id,
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
	stdout: 'Mounted on Use%\n/          96%\n/var       66%\n/boot      12%\n', stderr: j.status === 'failed' ? 'warning: / is above 95%\n' : '',
	stdout_len: 62, stderr_len: j.status === 'failed' ? 25 : 0
});
const scripts = [
	{ id: 's-disk', name: 'Disk usage report', description: 'Free space per mount, fullest first', interpreter: 'bash', body: 'df -h --output=target,pcent | sort -k2 -rn', timeout_secs: 120, client_id: null, client_name: null, created_at: ago(9000), updated_at: ago(2000) },
	{ id: 's-spool', name: 'Restart print spooler', description: 'Clears stuck print jobs', interpreter: 'powershell', body: 'Stop-Service Spooler -Force\nRemove-Item C:\\Windows\\System32\\spool\\PRINTERS\\* -Force\nStart-Service Spooler', timeout_secs: 60, client_id: 'c-acme', client_name: 'Acme Corp', created_at: ago(8000), updated_at: ago(300) },
	{ id: 's-upd', name: 'Pending updates', description: '', interpreter: 'python', body: 'import subprocess\nprint(subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True).stdout)', timeout_secs: 300, client_id: null, client_name: null, created_at: ago(7000), updated_at: ago(7000) }
];

const page = <T>(items: T[], limit = 1000) => ({ items: items.slice(0, limit), next: null, prev: null, total: items.length, total_exact: true });
function clientOut(c: (typeof clients)[number]) {
	return {
		...c,
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

const admin = { id: 'u-1', email: 'dana@northwind.example', name: 'Dana Admin', role: 'admin', totp_enabled: true, mfa_setup_required: false, client_ids: null, preferences: {} };

export async function mockApi(p: Page, opts: { signedIn?: boolean } = {}) {
	const signedIn = opts.signedIn ?? true;
	await p.clock.setFixedTime(NOW);
	await p.route('**/api/**', async (route: Route) => {
		const url = new URL(route.request().url());
		const path = url.pathname.replace(/^\/api/, '');
		// The live stream never answers: the dot shows "connecting" and pages keep their data.
		if (path === '/events') return;
		const q = url.searchParams;
		const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
		if (route.request().method() !== 'GET') return json({ ok: true });
		let m: RegExpMatchArray | null;
		if (path === '/settings/public') return json({ company_name: 'Northwind IT' });
		if (path === '/auth/me') return signedIn ? json(admin) : json({ error: 'not authenticated' }, 401);
		if (path === '/dashboard') return json(dashboard(q.get('client_id')));
		if (path === '/clients') return json(clients.map(clientOut));
		if ((m = path.match(/^\/clients\/([^/]+)$/))) return json(clientOut(clients.find((c) => c.id === m![1])!));
		if (path === '/agents') {
			let list = agents.filter((a) => (!q.get('client_id') || a.client_id === q.get('client_id')) && (!q.get('online') || String(a.online) === q.get('online')));
			if (q.get('health')) list = list.filter((a) => q.get('health')!.split(',').includes(a.health));
			if (q.get('new_days')) list = list.filter((a) => Date.parse(a.enrolled_at) > NOW.getTime() - Number(q.get('new_days')) * 86_400_000);
			if (q.get('os')) list = list.filter((a) => a.os_family === q.get('os'));
			if (q.get('q')) list = list.filter((a) => a.hostname.includes(q.get('q')!));
			return json(page(list, Number(q.get('limit') ?? 50)));
		}
		if ((m = path.match(/^\/agents\/([^/]+)$/))) return json(detail(agents.find((a) => a.id === m![1])!));
		if ((m = path.match(/^\/agents\/([^/]+)\/metrics$/))) return json(metricHistory(agents.find((a) => a.id === m![1])!));
		if (path.match(/^\/agents\/[^/]+\/activity$/)) return json([{ id: 1, ts: ago(300), user_name: 'Dana Admin', action: 'agent.update_offer', target_type: 'agent', target_id: 'a-1', details: { version: '0.4.2' } }, { id: 2, ts: ago(290), user_name: null, action: 'agent.update_completed', target_type: 'agent', target_id: 'a-1', details: { version: '0.4.2' } }]);
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
		if (path === '/users') return json([admin, { ...admin, id: 'u-2', email: 'terry@northwind.example', name: 'Terry Tech', role: 'technician', totp_enabled: false, client_ids: ['c-acme'] }].map((u) => ({ ...u, disabled: false, last_login_at: ago(60), all_clients: u.role === 'admin', client_ids: u.client_ids ?? [] })));
		if (path === '/settings') return json({ company_name: 'Northwind IT', session_idle_hours: null, session_idle_hours_default: 12, require_2fa_all: false, auto_update_agents: true });
		if (path === '/auth/totp') return json({ enabled: true, required: true, recovery_codes_left: 8 });
		if (path === '/auth/sessions') return json([{ id: 'x1', created_at: ago(600), last_seen_at: ago(0), expires_at: ago(-6000), user_agent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0', current: true }]);
		if (path.match(/^\/sites\/[^/]+\/enrollment-tokens$/)) return json([{ id: 't1', label: 'Office rollout', max_uses: 50, uses: 12, expires_at: ago(-60 * 24 * 20), created_at: ago(60 * 24 * 10) }]);
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
		if (path === '/alert-policies') return json(policies);
		if ((m = path.match(/^\/alert-policies\/([^/]+)$/))) return json(pol(m![1]));
		if (path === '/notification-channels') return json(channels);
		if (path === '/notifications') return json(deliveries);
		if (path === '/settings/smtp') return json({ host: 'smtp.office365.com', port: 587, security: 'starttls', username: 'rmm@northwind.example', password_set: true, from: 'Northwind RMM <rmm@northwind.example>' });
		if (path === '/schedules') return json(schedules);
		if (path === '/schedules/preview') return json({ runs: [1, 2, 3, 4, 5].map((d) => new Date(Date.UTC(2026, 5, 15 + d, 2, 0)).toISOString()) });
		if ((m = path.match(/^\/schedules\/([^/]+)$/))) return json(schedules.find((x) => x.id === m![1]));
		if (path.match(/^\/agents\/[^/]+\/services$/)) return json({ services, services_at: ago(3), alerting: ['nginx.service'] });
		if (path.match(/^\/agents\/[^/]+\/log-events$/)) return json(logEvents);
		if (path === '/search') return json({ agents: agents.filter((a) => a.hostname.includes(q.get('q') ?? '')).slice(0, 5).map((a) => ({ id: a.id, hostname: a.hostname, os_family: a.os_family, online: a.online, client_name: a.client_name, site_name: a.site_name })), clients: [], sites: [], scripts: [] });
		return json({ error: `no mock for ${path}` }, 404);
	});
}
