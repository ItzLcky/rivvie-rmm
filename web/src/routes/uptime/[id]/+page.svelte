<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { Pause, Pencil, Play, RefreshCw, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import Chart from '#lib/components/Chart.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import MonitorDrawer from '#lib/components/uptime/MonitorDrawer.svelte';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, cx, datetime, ms } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import { certDays, monitorKindLabel, monitorLabel, monitorTone, uptimePct, type MonitorDay, type MonitorDetail, type UptimePoint } from '#lib/uptime.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';

	const id = $derived(page.params.id);
	const hours = $derived(Number(param('hours', '24')) || 24);
	const monitor = resource(() => api.get<MonitorDetail>(`/uptime/monitors/${id}`));
	const points = resource(() => api.get<UptimePoint[]>(`/uptime/monitors/${id}/results?from=${encodeURIComponent(new Date(Date.now() - hours * 3600_000).toISOString())}`));
	liveReload(() => { monitor.reload(); points.reload(); }, (e) => e.type === 'alert' || (e.type === 'monitor' && e.id === id), { debounceMs: 1500, pollMs: 30000 });
	let editing = $state(false);

	const latency = $derived((points.data ?? []).flatMap((p) => (p.avg_ms == null ? [] : [{ t: new Date(p.ts).getTime(), v: p.avg_ms }])));
	const passed = $derived((points.data ?? []).flatMap((p) => (p.checks ? [{ t: new Date(p.ts).getTime(), v: (100 * (p.checks - p.failures)) / p.checks }] : [])));
	const latencyMax = $derived(Math.max(10, ...latency.map((p) => p.v)));

	/** The last 90 days, oldest first, with gaps for days without checks. */
	function ninety(days: MonitorDay[]): (MonitorDay & { label: string })[] {
		const by = new Map(days.map((d) => [d.day.slice(0, 10), d]));
		const out = [];
		const today = new Date();
		for (let i = 89; i >= 0; i--) {
			const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i));
			const key = d.toISOString().slice(0, 10);
			const row = by.get(key) ?? { day: key, checks: 0, failures: 0, uptime: null };
			out.push({ ...row, label: d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' }) });
		}
		return out;
	}
	const dayTone = (u: number | null) => (u == null ? 'bg-sunken' : u >= 99.9 ? 'bg-success' : u >= 99 ? 'bg-warning-dot' : 'bg-danger');

	async function checkNow() {
		if (await attempt(() => api.post(`/uptime/monitors/${id}/check`), 'Asked the agent to check it now.')) setTimeout(() => monitor.reload(), 3000);
	}
	async function toggle(enabled: boolean) {
		if (await attempt(() => api.put(`/uptime/monitors/${id}`, { enabled }), enabled ? 'Checking again.' : 'Switched off: no checks, and its alerts are closed.')) monitor.reload();
	}
	async function remove() {
		const m = monitor.data!;
		const ok = await confirmAction({ title: `Delete ${m.name}?`, message: 'Its history and open alerts are deleted.', confirmLabel: 'Delete monitor', danger: true });
		if (ok && (await attempt(() => api.del(`/uptime/monitors/${id}`), `${m.name} deleted.`))) await goto('/uptime');
	}
</script>

<Async res={monitor}>
	{#snippet children(m)}
		<PageHeader title={m.name} crumbs={[{ label: 'Uptime', href: '/uptime' }, { label: `${m.client_name} › ${m.site_name}` }]}>
			{#snippet meta()}
				<Badge tone={m.enabled ? monitorTone[m.state] : 'neutral'}>{m.enabled ? monitorLabel[m.state] : 'Off'}</Badge>
				<span class="text-muted text-sm">{monitorKindLabel(m.kind)} · <span class="font-mono">{m.target}</span></span>
			{/snippet}
			{#snippet actions()}
				{#if can('technician')}
					<Button icon={RefreshCw} onclick={checkNow} disabled={!m.enabled}>Check now</Button>
					<Button icon={Pencil} onclick={() => (editing = true)}>Edit</Button>
					{#if m.enabled}<Button icon={Pause} onclick={() => toggle(false)}>Switch off</Button>{:else}<Button icon={Play} onclick={() => toggle(true)}>Switch on</Button>{/if}
					<Button variant="danger-ghost" icon={Trash2} onclick={remove}>Delete</Button>
				{/if}
			{/snippet}
		</PageHeader>

		{#if m.enabled && m.state === 'down' && m.last_message}
			<p class="border-danger/40 bg-danger-soft text-danger mb-4 rounded-md border px-3 py-2 text-sm" role="status">Failing {m.fail_count} {m.fail_count === 1 ? 'check' : 'checks'} in a row: {m.last_message}</p>
		{/if}
		{#if m.enabled && !m.runner_online}
			<p class="border-warning/40 bg-warning-soft text-warning mb-4 rounded-md border px-3 py-2 text-sm" role="status">
				{m.runner_hostname ? `${m.runner_hostname}, which checks this monitor, is offline` : 'No agent checks this monitor: pick one, or designate one for the site under Network → Settings'}. Its state is unknown until it checks again.
			</p>
		{/if}

		<section class="card mb-5 p-4" aria-label="Availability over 90 days">
			<div class="mb-3 flex flex-wrap items-baseline justify-between gap-2">
				<h2 class="text-sm font-semibold">Availability, 90 days</h2>
				<span class="text-muted text-sm">24 hours <span class="text-fg tabular font-medium">{uptimePct(m.uptime_24h)}</span> · 30 days <span class="text-fg tabular font-medium">{uptimePct(m.uptime_30d)}</span></span>
			</div>
			<div class="flex h-8 items-stretch gap-px" role="img" aria-label="One bar per day, the last 90 days: green 99.9% or more of checks passed, amber 99%, red less, grey no checks">
				{#each ninety(m.days) as d (d.day)}
					<div class={cx('min-w-0 flex-1 rounded-[1px]', dayTone(d.uptime))} title="{d.label}: {d.checks ? `${uptimePct(d.uptime)} (${d.failures} of ${d.checks} failed)` : 'no checks'}"></div>
				{/each}
			</div>
			<div class="text-muted mt-1 flex justify-between text-xs"><span>90 days ago</span><span>Today</span></div>
		</section>

		<div class="mb-5 grid gap-5 lg:grid-cols-3">
			<section class="card p-4" aria-label="Details">
				<h2 class="mb-3 text-sm font-semibold">Details</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
					<dt class="text-muted">Last check</dt><dd title={datetime(m.last_at)}>{m.last_at ? ago(m.last_at) : 'never'}</dd>
					<dt class="text-muted">Result</dt><dd class="break-words">{m.last_message ?? '–'}</dd>
					<dt class="text-muted">Response</dt><dd>{m.last_ms != null ? ms(m.last_ms) : '–'}</dd>
					<dt class="text-muted">State since</dt><dd title={datetime(m.state_since)}>{ago(m.state_since)}</dd>
					<dt class="text-muted">Every</dt><dd>{m.interval_secs} s, timeout {m.timeout_secs} s</dd>
					<dt class="text-muted">Checked by</dt>
					<dd>{#if m.runner_agent_id}<a class="link" href="/agents/{m.runner_agent_id}">{m.runner_hostname}</a>{m.agent_id ? '' : ' (designated agent)'}{:else}–{/if}</dd>
				</dl>
			</section>

			<section class="card p-4" aria-label="Certificate">
				<h2 class="mb-3 text-sm font-semibold">Certificate</h2>
				{#if m.cert}
					{@const d = certDays(m.cert.not_after)}
					<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
						<dt class="text-muted">Expires</dt>
						<dd><span title={datetime(m.cert.not_after)}>{new Date(m.cert.not_after).toLocaleDateString()}</span> <Badge tone={d != null && d < 0 ? 'danger' : d != null && d <= 14 ? 'warning' : 'neutral'}>{d != null && d < 0 ? 'expired' : `${d} days`}</Badge></dd>
						<dt class="text-muted">Subject</dt><dd class="break-words">{m.cert.subject}</dd>
						<dt class="text-muted">Issuer</dt><dd class="break-words">{m.cert.issuer}</dd>
						<dt class="text-muted">Names</dt><dd class="font-mono text-xs break-words">{m.cert.sans.join(', ') || '–'}</dd>
						<dt class="text-muted">Trusted</dt><dd>{m.cert.untrusted ? `No: ${m.cert.untrusted}` : 'Yes, by the agent’s machine'}</dd>
					</dl>
				{:else}
					<p class="text-muted text-sm">{m.kind === 'tls' || (m.kind === 'http' && m.target.startsWith('https')) ? 'Not read yet.' : 'Only TLS monitors and https:// websites have one.'}</p>
				{/if}
			</section>

			<section class="card p-4" aria-label="Open alerts">
				<h2 class="mb-3 text-sm font-semibold">Open alerts</h2>
				{#if m.alerts.length}
					<ul class="space-y-2 text-sm">
						{#each m.alerts as a (a.id)}
							<li class="flex items-start gap-2"><SeverityBadge severity={a.severity} /><a class="hover:text-accent min-w-0 flex-1" href="/alerts/{a.id}">{a.title}<span class="text-muted block text-xs">{ago(a.opened_at)}{a.acknowledged_at ? ' · acknowledged' : ''}</span></a></li>
						{/each}
					</ul>
				{:else}
					<p class="text-muted text-sm">None. Alerts come from an <em>Uptime monitor</em> item under <a class="link" href="/policies">Policies</a>, in the checking agent’s policy set.</p>
				{/if}
			</section>
		</div>

		<div class="mb-3 flex flex-wrap items-center justify-between gap-2">
			<h2 class="text-lg font-semibold">History</h2>
			<Segmented label="Time range" value={String(hours)} onchange={(v) => setParams({ hours: v === '24' ? null : v })} options={[{ value: '24', label: '24 hours' }, { value: '168', label: '7 days' }, { value: '720', label: '30 days' }]} />
		</div>
		<div class="mb-6 grid gap-4 md:grid-cols-2">
			<div class="card p-4"><Chart label="Response time (ms)" points={latency} max={latencyMax} unit="" /></div>
			<div class="card p-4"><Chart label="Checks passed" points={passed} unit="%" color="var(--chart-2)" /></div>
		</div>

		<section aria-label="Latest checks">
			<h2 class="mb-3 text-lg font-semibold">Latest checks</h2>
			<div class="card overflow-x-auto">
				<table class="w-full text-sm">
					<caption class="sr-only">The latest checks of {m.name}</caption>
					<thead class="text-muted border-border border-b text-left text-xs"><tr><th class="px-3 py-2">When</th><th class="px-3 py-2">Result</th><th class="px-3 py-2 text-right">Response</th><th class="px-3 py-2">Message</th></tr></thead>
					<tbody class="divide-border divide-y">
						{#each m.recent as r (r.ts)}
							<tr>
								<td class="text-muted px-3 py-2 whitespace-nowrap" title={datetime(r.ts)}>{ago(r.ts)}</td>
								<td class="px-3 py-2"><Badge tone={r.ok ? 'success' : 'danger'}>{r.ok ? 'Passed' : 'Failed'}</Badge></td>
								<td class="tabular px-3 py-2 text-right whitespace-nowrap">{r.ms != null ? ms(r.ms) : '–'}</td>
								<td class="text-muted px-3 py-2">{r.message}</td>
							</tr>
						{:else}
							<tr><td colspan="4" class="text-muted px-3 py-6 text-center">No checks yet.</td></tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>

		{#if editing}
			<MonitorDrawer monitor={m} onclose={() => (editing = false)} ondone={() => ((editing = false), monitor.reload(), points.reload())} />
		{/if}
	{/snippet}
</Async>
