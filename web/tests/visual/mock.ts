/**
 * A mocked API for the visual tests: a small fleet with fixed data and timestamps relative to
 * NOW (the page clock is frozen there), so every screenshot is the same on every run.
 */
import type { Page, Route } from '@playwright/test';

export const NOW = new Date('2026-06-15T14:30:00Z');
const ago = (mins: number) => new Date(NOW.getTime() - mins * 60_000).toISOString();

const clients = [
	{ id: 'c-acme', name: 'Acme Corp', created_at: ago(60 * 24 * 200), desktop_consent: true },
	{ id: 'c-globex', name: 'Globex', created_at: ago(60 * 24 * 90), desktop_consent: false },
	{ id: 'c-initech', name: 'Initech', created_at: ago(60 * 24 * 30), desktop_consent: false },
	{ id: 'c-umbrella', name: 'Umbrella Health', created_at: ago(60 * 24 * 3), desktop_consent: true }
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
		patches_overdue: 0, patches_failed: 0, reboot_pending: false, reboot_pending_since: null as string | null, alerts_muted: false
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
const policyRow = (o: Record<string, unknown>) => ({
	id: 'p-global', client_id: null, site_id: null, client_name: null, site_name: null, auto_approve_severities: [], auto_approve_categories: ['security', 'critical', 'definition'],
	deferral_days: 0, auto_install: false, reboot_policy: 'never', updated_by_name: 'Dana Admin', updated_at: ago(60 * 24 * 6), agents: 4, ...o
});
const patchPolicies = [
	policyRow({}),
	policyRow({ id: 'p-acme', client_id: 'c-acme', client_name: 'Acme Corp', auto_approve_severities: ['critical'], deferral_days: 2, auto_install: true, reboot_policy: 'if_required', agents: 3, updated_at: ago(60 * 26) }),
	policyRow({ id: 'p-acme-wh', client_id: 'c-acme', site_id: 's-acme-wh', client_name: 'Acme Corp', site_name: 'Warehouse', auto_approve_categories: ['security', 'definition'], auto_install: true, reboot_policy: 'always', agents: 1, updated_at: ago(60 * 5) })
];
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
		policy: { ...(a.client_id === 'c-acme' ? (a.site_id === 's-acme-wh' ? patchPolicies[2] : patchPolicies[1]) : patchPolicies[0]), source: a.client_id === 'c-acme' ? (a.site_id === 's-acme-wh' ? 'site' : 'client') : 'global' },
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
				ev(8, 'message', 45, { public: true, author_contact_id: 'ct-ann', author_kind: 'contact', author_name: 'Ann Lopez', body: 'Thanks, will do!', data: { from: 'ann@acme.example' } })
			]
		: [ev(1, 'created', 60, { author_name: 'Alert', body: `${t.subject}\nSeverity: critical` }), ev(2, 'alert', 60, { author_name: 'Alert', data: { alert_id: 'al-1', state: 'opened' } })];
	return {
		...t, events, attachments: t.id === 't-1' ? [{ id: 'at-1', event_id: 1, name: 'test-page.pdf', content_type: 'application/pdf', size: 182_400, uploaded_by_name: null, created_at: ago(300) }] : [],
		agents: [{ ...a, capabilities: ['patch', 'desktop'], reboot_pending: false, missing_patches: 3, alerts: alerts.filter((x) => x.agent_id === a.id && x.state !== 'resolved').slice(0, 3).map((x) => ({ id: x.id, title: x.title, severity: x.severity, opened_at: x.opened_at })) }],
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
		isolated: sensors[a.id].isolated, sensor: sensors[a.id].sensor, content_version: (sensors[a.id].sensor?.content_version as string | null) ?? null
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
const sensorPolicy = (o: Record<string, unknown> = {}) => ({
	enabled: true, quick_scan_hours: 24, full_scan_days: 7, auto_quarantine: true, prevention: true, telemetry_mb: 256, canaries: true,
	exclusions: [{ kind: 'path', value: 'D:\\Backups\\' }], rule_modes: [], ...o
});
const health = (o: Record<string, unknown> = {}) => ({
	events_total: 1_284_330, events_per_min: 212.4, store_bytes: 141 * 2 ** 20, cpu_percent: 0.8, rss_bytes: 38 * 2 ** 20, rules: 64,
	collectors: [['process', 'etw'], ['network', 'etw'], ['file', 'etw'], ['registry', 'etw']], canaries: 6, last_scan: ago(60 * 5), ...o
});
const sensors: Record<string, { sensor: Record<string, unknown> | null; policy: Record<string, unknown>; isolated: boolean }> = {
	'a-1': { sensor: { enabled: true, running: true, restarts: 4, content_version: '2026.06.14.1', error: null, isolated: false, health: health({ events_per_min: 96.1, cpu_percent: 1.4 }) }, policy: sensorPolicy(), isolated: false },
	'a-2': { sensor: { enabled: true, running: true, restarts: 0, content_version: '2026.06.14.1', error: null, isolated: true, health: health() }, policy: sensorPolicy(), isolated: true },
	'a-3': { sensor: { enabled: true, running: false, restarts: 2, content_version: '2026.06.10.2', error: 'fanotify: permission denied (the agent needs CAP_SYS_ADMIN)', isolated: false, health: null }, policy: sensorPolicy({ prevention: false, canaries: false }), isolated: false },
	'a-4': { sensor: { enabled: true, running: true, restarts: 0, content_version: '2026.06.10.2', error: null, isolated: false, health: health({ events_per_min: 40 }) }, policy: sensorPolicy(), isolated: false },
	'a-5': { sensor: { enabled: false, running: false, restarts: 0, content_version: null, error: null, isolated: false, health: null }, policy: sensorPolicy({ enabled: false }), isolated: false },
	'a-6': { sensor: { enabled: true, running: true, restarts: 0, content_version: '2026.06.14.1', error: null, isolated: false, health: health({ collectors: [['process', 'proc-connector'], ['network', 'poll'], ['file', 'fanotify']], canaries: 0 }) }, policy: sensorPolicy({ canaries: false }), isolated: false },
	'a-7': { sensor: null, policy: sensorPolicy(), isolated: false }
};
const rmmProduct = (a: string): Prod => ({
	kind: 'rmm', name: 'RMM sensor', version: '0.4.2', enabled: true, realtime: true, signature_version: '2026.06.14.1', signatures_updated_at: ago(60 * 20),
	signatures_current: null, last_quick_scan_at: ago(60 * 5), last_full_scan_at: ago(60 * 24 * 3), tamper_protection: null, actions: ['quick_scan', 'full_scan'], detail: a === 'a-1' ? 'Engine 0.4.2' : null
});
security['a-1'].products.push(rmmProduct('a-1'));
security['a-2'].products.push(rmmProduct('a-2'));
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
	{ id: 'd-7', agent_id: 'a-1', product: 'rmm', source: 'behaviour', name: 'Scheduled task created from a temp folder', severity: 'moderate', status: 'active', resources: [], process: 'C:\\Windows\\System32\\schtasks.exe', username: 'ACME\\dana', detected_at: ago(60 * 9), first_seen_at: ago(60 * 9), last_seen_at: ago(60 * 9), resolved_at: null, rule_id: 'RMM-B-0031', mitre: ['T1053.005'], audit: true, action_taken: null, sha256: null, verdict: 'benign' }
].map((d) => {
	const a = agents.find((x) => x.id === d.agent_id)!;
	return { ...d, hostname: a.hostname, client_id: a.client_id, client_name: a.client_name, site_name: a.site_name };
});
const allDetections = [
	...extraDetections.slice(0, 2),
	...detections.map((d) => ({ ...d, source: 'product', rule_id: null, mitre: [] as string[], audit: false, action_taken: d.status === 'active' ? null : d.status === 'quarantined' ? 'Quarantined' : 'Removed', sha256: d.id === 'd-3' ? '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' : null, verdict: d.id === 'd-3' ? 'benign' : null })),
	extraDetections[2]
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
		isolated: z.isolated, policy: z.policy, quarantine: quarantine.filter((q) => q.agent_id === a.id && q.state === 'quarantined')
	};
}
function detectionDetail(id: string) {
	const d = allDetections.find((x) => x.id === id)!;
	const a = agents.find((x) => x.id === d.agent_id)!;
	const isD5 = d.id === 'd-5';
	return {
		...d, os_family: a.os_family, online: a.online, isolated: sensors[a.id].isolated, context: isD5 ? contextD5 : [], context_unavailable: false,
		content_version: d.product === 'rmm' ? '2026.06.14.1' : null, notes: d.verdict ? 'Confirmed with the user: opened an invoice from an unknown sender.' : null,
		verdict_by_name: d.verdict ? 'Dana Admin' : null, verdict_at: d.verdict ? ago(15) : null, quarantine_id: d.id === 'd-6' ? 'q-1' : null,
		prevalence: d.sha256 === HASH_BEACON || isD5 ? [{ agent_id: 'a-4', hostname: 'acme-pos-07', client_name: 'Acme Corp', first_seen: ago(60 * 3), how: 'Quarantined (RMM-F-0002)' }] : [],
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
const securityPolicies = [
	{ id: 'sp-global', client_id: null, client_name: null, site_id: null, site_name: null, sensor_enabled: true, quick_scan_hours: 24, full_scan_days: 7, auto_quarantine: true, prevention: true, canaries: true, telemetry_mb: 256, updated_by_name: 'Dana Admin', updated_at: ago(60 * 24 * 6) },
	{ id: 'sp-globex', client_id: 'c-globex', client_name: 'Globex', site_id: null, site_name: null, sensor_enabled: true, quick_scan_hours: 12, full_scan_days: 0, auto_quarantine: true, prevention: false, canaries: false, telemetry_mb: 512, updated_by_name: 'Terry Tech', updated_at: ago(60 * 30) },
	{ id: 'sp-umbrella', client_id: 'c-umbrella', client_name: 'Umbrella Health', site_id: 's-umbrella', site_name: 'Clinic', sensor_enabled: false, quick_scan_hours: 24, full_scan_days: 7, auto_quarantine: true, prevention: false, canaries: false, telemetry_mb: 256, updated_by_name: 'Dana Admin', updated_at: ago(60 * 24 * 2) }
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
			searched: 4, offline: 1, errors: [{ agent_id: 'a-3', hostname: 'acme-web01', error: 'the sensor isn’t running' }]
		}
	};
}

const admin = { id: 'u-1', email: 'dana@northwind.example', name: 'Dana Admin', role: 'admin', totp_enabled: true, mfa_setup_required: false, client_ids: null, preferences: {}, permissions: ['security.read', 'security.respond', 'security.manage'] };

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
		if (path === '/security/hunt' && route.request().method() === 'POST') {
			const r = hunt(route.request().postDataJSON() ?? {});
			return json(r.body, r.status);
		}
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
		if (path === '/security/prevalence') return json({ sha256: q.get('sha256'), agents: q.get('sha256') === HASH_BEACON ? detectionDetail('d-6').prevalence.concat([{ agent_id: 'a-2', hostname: 'acme-fs01', client_name: 'Acme Corp', first_seen: ago(26), how: 'Detected and quarantined (RMM-F-0002)' }]) : [] });
		if (path === '/security/rules') return json(rules);
		if (path === '/security/content') return json({ versions: contentVersions, canary_clients: 1, soak_minutes: 1440, verifies_signatures: false });
		if (path === '/security/policies') return json(securityPolicies);
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
		if (path === '/patch-policies') return json(patchPolicies);
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
				].map((u) => ({ ...u, disabled: false, last_login_at: ago(60), all_clients: u.role === 'admin' || u.client_ids === null, client_ids: u.client_ids ?? [] }))
			);
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
		if ((m = path.match(/^\/agents\/([^/]+)\/alert-policies$/))) {
			const a = agents.find((x) => x.id === m![1])!;
			return json(
				policies
					.filter((p) => (!p.client_id || p.client_id === a.client_id) && (!p.site_id || p.site_id === a.site_id) && (!p.os_family || p.os_family === a.os_family))
					.map((p) => ({ id: p.id, name: p.name, kind: p.kind, severity: p.severity, enabled: p.enabled, level: p.site_id ? 'site' : p.client_id ? 'client' : 'msp', excluded: p.excluded.some((x) => x.id === a.id), editable: true, open_alerts: alerts.filter((al) => al.policy_id === p.id && al.agent_id === a.id && al.state !== 'resolved').length }))
			);
		}
		if (path === '/alert-mutes') {
			const list = mutes.filter((x) => (!q.get('client_id') || x.owner_client_id === q.get('client_id')) && (!q.get('agent_id') || x.agent_id === q.get('agent_id') || x.site_id === agents.find((a) => a.id === q.get('agent_id'))?.site_id));
			return json(list);
		}
		if ((m = path.match(/^\/agents\/([^/]+)\/processes$/))) return json({ processes });
		if ((m = path.match(/^\/agents\/([^/]+)\/files$/))) return json(listing(q.get('path') ?? ''));
		if ((m = path.match(/^\/alert-policies\/([^/]+)$/))) return json(pol(m![1]));
		if (path === '/notification-channels') return json(channels);
		if (path === '/notifications') return json(deliveries);
		if (path === '/settings/smtp') return json({ host: 'smtp.office365.com', port: 587, security: 'starttls', username: 'rmm@northwind.example', password_set: true, from: 'Northwind RMM <rmm@northwind.example>' });
		if (path === '/schedules') return json(schedules);
		if (path === '/schedules/preview') return json({ runs: [1, 2, 3, 4, 5].map((d) => new Date(Date.UTC(2026, 5, 15 + d, 2, 0)).toISOString()) });
		if ((m = path.match(/^\/schedules\/([^/]+)$/))) return json(schedules.find((x) => x.id === m![1]));
		if (path.match(/^\/agents\/[^/]+\/services$/)) return json({ services, services_at: ago(3), alerting: ['nginx.service'] });
		if (path.match(/^\/agents\/[^/]+\/log-events$/)) return json(logEvents);
		if (path === '/tickets/summary') return json({ open: 4, mine: 1, unassigned: 2, triage: 1, waiting: 1, team: 0, breached: 0 });
		if (path === '/tickets/meta') return json({ boards, types: ticketTypes, technicians: [{ id: 'u-1', name: 'Dana Admin', email: admin.email, client_ids: null }, { id: 'u-2', name: 'Terry Tech', email: 'terry@northwind.example', client_ids: ['c-acme', 'c-globex'] }], teams: [] });
		if (path === '/tickets') return json(page(ticketList(q), Number(q.get('limit') ?? 50)));
		if ((m = path.match(/^\/tickets\/([^/]+)$/))) return json(ticketDetail(tickets.find((t) => t.id === m![1])!));
		if (path === '/contacts') return json(contacts.filter((c) => !q.get('client_id') || c.client_id === q.get('client_id')));
		if (path === '/boards') return json(boards);
		if (path === '/mailboxes') return json(mailboxes);
		if (path === '/mailboxes/inbound') return json(inboundMail);
		if (path === '/search') return json({ agents: agents.filter((a) => a.hostname.includes(q.get('q') ?? '')).slice(0, 5).map((a) => ({ id: a.id, hostname: a.hostname, os_family: a.os_family, online: a.online, client_name: a.client_name, site_name: a.site_name })), clients: [], sites: [], scripts: [], tickets: [] });
		if (path === '/canned-responses' || path === '/teams' || path === '/charges' || path === '/products' || path === '/sla/policies' || path === '/sla/calendars') return json([]);
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
