<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { Pause, Pencil, Play, RefreshCw, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import Chart from '#lib/components/Chart.svelte';
	import DeviceDialog from '#lib/components/network/DeviceDialog.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, bytes, datetime, duration, ms, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { bps, discoveredTone, ifStatus, kindLabel, stateLabel, stateTone, type DeviceDetail, type DevicePoint, type InterfacePoint, type NetInterface } from '#lib/network.js';
	import { resource } from '#lib/resource.svelte.js';
	import { withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	const id = $derived(page.params.id);
	const hours = $derived(Number(param('hours', '24')) || 24);
	const device = resource(() => api.get<DeviceDetail>(`/network/devices/${id}`));
	const points = resource(() => api.get<DevicePoint[]>(`/network/devices/${id}/metrics?hours=${hours}`));
	liveReload(() => { device.reload(); points.reload(); }, (e) => e.type === 'alert', { debounceMs: 2000, pollMs: 30000 });

	let editing = $state(false);
	const ifIndex = $derived(Number(param('port')) || null);
	const ifPoints = resource(() => (ifIndex ? api.get<InterfacePoint[]>(`/network/devices/${id}/interfaces/${ifIndex}/metrics?hours=${hours}`) : Promise.resolve([] as InterfacePoint[])));

	const series = (rows: DevicePoint[] | undefined, v: (p: DevicePoint) => number | null) =>
		(rows ?? []).flatMap((p) => {
			const x = v(p);
			return x == null ? [] : [{ t: new Date(p.ts).getTime(), v: x }];
		});
	const cpu = $derived(series(points.data, (p) => p.cpu_percent));
	const mem = $derived(series(points.data, (p) => (p.mem_total ? (100 * (p.mem_used ?? 0)) / p.mem_total : null)));
	const reach = $derived(series(points.data, (p) => p.reachable_pct));
	const rtt = $derived(series(points.data, (p) => p.rtt_ms));
	const rttMax = $derived(Math.max(10, ...rtt.map((p) => p.v)));
	const ifSeries = (v: (p: InterfacePoint) => number | null, scale = 1) =>
		(ifPoints.data ?? []).flatMap((p) => {
			const x = v(p);
			return x == null ? [] : [{ t: new Date(p.ts).getTime(), v: x / scale }];
		});
	const inSeries = $derived(ifSeries((p) => p.in_bps, 1e6));
	const outSeries = $derived(ifSeries((p) => p.out_bps, 1e6));
	const trafficMax = $derived(Math.max(1, ...inSeries.map((p) => p.v), ...outSeries.map((p) => p.v)));
	const chosen = $derived(device.data?.interfaces.find((i) => i.if_index === ifIndex));

	async function pollNow() {
		if (await attempt(() => api.post(`/network/devices/${id}/poll`), 'Asked the agent to read it now.')) setTimeout(() => device.reload(), 3000);
	}
	async function toggle(enabled: boolean) {
		if (await attempt(() => api.put(`/network/devices/${id}`, { enabled }), enabled ? 'Resumed.' : 'Paused: it is not read and its alerts are closed.')) device.reload();
	}
	async function remove() {
		const d = device.data!;
		const ok = await confirmAction({ title: `Stop monitoring ${d.name}?`, message: 'Its history and open alerts are deleted. The host can be found again by the next scan.', confirmLabel: 'Delete device', danger: true });
		if (ok && (await attempt(() => api.del(`/network/devices/${id}`), `${d.name} removed.`))) await goto(withClient('/network'));
	}
	async function monitorPort(i: NetInterface, monitored: boolean) {
		if (await attempt(() => api.put(`/network/devices/${id}/interfaces/${i.if_index}`, { monitored }))) device.reload();
	}
	const supplyName = (k: number) => ({ 3: 'Toner', 4: 'Waste toner', 5: 'Ink', 9: 'Drum', 12: 'Fuser' })[k];
	const portTone = (i: NetInterface) => (i.oper_status === 1 ? 'success' : i.admin_status === 2 ? 'neutral' : 'danger') as 'success' | 'neutral' | 'danger';
	const portText = (i: NetInterface) => (i.admin_status === 2 ? 'Disabled' : i.oper_status === 1 ? 'Up' : ifStatus(i.oper_status).replace(/^./, (c) => c.toUpperCase()));
</script>

<Async res={device}>
	{#snippet children(d)}
		<PageHeader
			title={d.name}
			crumbs={[{ label: 'Network', href: withClient('/network') }, { label: `${d.client_name} › ${d.site_name}` }]}
		>
			{#snippet meta()}
				<Badge tone={d.enabled ? stateTone[d.state] : 'neutral'}>{d.enabled ? stateLabel[d.state] : 'Paused'}</Badge>
				<span class="text-muted text-sm">{kindLabel(d.kind)} · <span class="font-mono">{d.host}{d.port !== 161 ? `:${d.port}` : ''}</span></span>
			{/snippet}
			{#snippet subtitle()}
				<span class="text-muted text-sm">{d.sys_descr ?? ''}</span>
			{/snippet}
			{#snippet actions()}
				{#if can('technician')}
					<Button icon={RefreshCw} onclick={pollNow} disabled={!d.enabled}>Read now</Button>
					<Button icon={Pencil} onclick={() => (editing = true)}>Edit</Button>
					{#if d.enabled}<Button icon={Pause} onclick={() => toggle(false)}>Pause</Button>{:else}<Button icon={Play} onclick={() => toggle(true)}>Resume</Button>{/if}
					<Button variant="danger-ghost" icon={Trash2} onclick={remove}>Delete</Button>
				{/if}
			{/snippet}
		</PageHeader>

		{#if d.last_error && d.state !== 'up'}
			<p class="border-danger/40 bg-danger-soft text-danger mb-4 rounded-md border px-3 py-2 text-sm" role="status">Last reading failed: {d.last_error}</p>
		{/if}
		{#if !d.agent_online}
			<p class="border-warning/40 bg-warning-soft text-warning mb-4 rounded-md border px-3 py-2 text-sm" role="status">
				{d.agent_hostname ? `${d.agent_hostname}, the designated agent, is offline` : 'The site has no designated agent'}: this device isn't being read, so what's shown may be old.
			</p>
		{/if}

		<div class="mb-5 grid gap-5 lg:grid-cols-3">
			<section class="card p-4" aria-label="Details">
				<h2 class="mb-3 text-sm font-semibold">Details</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
					<dt class="text-muted">Uptime</dt><dd>{d.uptime_secs != null ? duration(d.uptime_secs) : '–'}</dd>
					<dt class="text-muted">Response</dt><dd>{d.rtt_ms != null ? ms(d.rtt_ms) : '–'}</dd>
					<dt class="text-muted">Last read</dt><dd title={datetime(d.last_poll_at)}>{d.last_poll_at ? ago(d.last_poll_at) : 'never'}</dd>
					<dt class="text-muted">Vendor</dt><dd>{d.vendor ?? '–'}</dd>
					<dt class="text-muted">MAC address</dt><dd class="font-mono text-[13px]">{d.mac ?? '–'}</dd>
					<dt class="text-muted">Location</dt><dd>{d.sys_location || '–'}</dd>
					<dt class="text-muted">Object ID</dt><dd class="font-mono text-xs break-all">{d.sys_object_id ?? '–'}</dd>
					<dt class="text-muted">Credentials</dt><dd>{d.credential_name}</dd>
					<dt class="text-muted">Read by</dt><dd>{#if d.agent_id}<a class="link" href="/agents/{d.agent_id}">{d.agent_hostname}</a>{:else}–{/if}</dd>
				</dl>
			</section>

			<section class="card p-4" aria-label="Health" >
				<h2 class="mb-3 text-sm font-semibold">Load</h2>
				<div class="space-y-3 text-sm">
					{#if d.cpu_percent != null}<div><div class="text-muted mb-1 text-xs">CPU</div><UsageBar value={d.cpu_percent} /></div>{/if}
					{#if d.mem_total}<div><div class="text-muted mb-1 text-xs">Memory · {bytes(d.mem_used)} of {bytes(d.mem_total)}</div><UsageBar value={(100 * (d.mem_used ?? 0)) / d.mem_total} /></div>{/if}
					{#each d.storage.filter((s) => s.kind === 'disk') as s (s.descr)}
						<div><div class="text-muted mb-1 truncate text-xs">{s.descr} · {bytes(s.used)} of {bytes(s.total)}</div><UsageBar value={s.total ? (100 * s.used) / s.total : 0} /></div>
					{/each}
					{#if d.cpu_percent == null && !d.mem_total && !d.storage.length}<p class="text-muted">The device doesn't report load.</p>{/if}
				</div>
			</section>

			<section class="card p-4" aria-label="Open alerts">
				<h2 class="mb-3 text-sm font-semibold">Open alerts</h2>
				{#if d.alerts.length}
					<ul class="space-y-2 text-sm">
						{#each d.alerts as a (a.id)}
							<li class="flex items-start gap-2"><SeverityBadge severity={a.severity} /><a class="hover:text-accent min-w-0 flex-1" href="/alerts/{a.id}">{a.title}<span class="text-muted block text-xs">{ago(a.opened_at)}{a.acknowledged_at ? ' · acknowledged' : ''}</span></a></li>
						{/each}
					</ul>
				{:else}
					<p class="text-muted text-sm">None. Set up alerts for network devices under <a class="link" href="/policies">Policies</a>, on the designated agent's policy set.</p>
				{/if}
			</section>
		</div>

		{#if d.supplies.length}
			<section class="card mb-5 p-4" aria-label="Supplies">
				<h2 class="mb-3 text-sm font-semibold">Supplies</h2>
				<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
					{#each d.supplies as s (s.index)}
						<div>
							<div class="text-muted mb-1 truncate text-xs">{s.description || supplyName(s.kind) || 'Supply'}{s.class === 4 ? ' (how full)' : ''}</div>
							{#if s.percent != null}
								{@const low = s.class === 4 ? s.percent >= 90 : s.percent <= 10}
								{@const warn = s.class === 4 ? s.percent >= 75 : s.percent <= 25}
								<div class="flex items-center gap-2" role="meter" aria-label={s.description} aria-valuemin={0} aria-valuemax={100} aria-valuenow={s.percent}>
									<div class="bg-sunken h-2 flex-1 overflow-hidden rounded-full"><div class="h-full rounded-full {low ? 'bg-danger' : warn ? 'bg-warning-dot' : 'bg-success'}" style="width: {s.percent}%"></div></div>
									<span class="tabular w-10 text-right text-sm {low ? 'text-danger font-medium' : warn ? 'text-warning font-medium' : ''}">{s.percent}%</span>
								</div>
							{:else}<span class="text-muted text-sm">Level unknown</span>{/if}
						</div>
					{/each}
				</div>
			</section>
		{/if}

		<div class="mb-3 flex flex-wrap items-center justify-between gap-2">
			<h2 class="text-lg font-semibold">History</h2>
			<Segmented label="Time range" value={String(hours)} onchange={(v) => setParams({ hours: v === '24' ? null : v })} options={[{ value: '24', label: '24 hours' }, { value: '168', label: '7 days' }, { value: '720', label: '30 days' }]} />
		</div>
		<div class="mb-6 grid gap-4 md:grid-cols-2">
			<div class="card p-4"><Chart label="Reachable" points={reach} unit="%" /></div>
			<div class="card p-4"><Chart label="Response time (ms)" points={rtt} max={rttMax} unit="" /></div>
			{#if cpu.length}<div class="card p-4"><Chart label="CPU" points={cpu} /></div>{/if}
			{#if mem.length}<div class="card p-4"><Chart label="Memory" points={mem} /></div>{/if}
		</div>

		<section aria-label="Ports">
			<h2 class="mb-3 text-lg font-semibold">Ports <span class="text-muted text-sm font-normal">{d.interfaces.length ? `${d.interfaces.filter((i) => i.oper_status === 1).length} of ${d.interfaces.length} up` : ''}</span></h2>
			{#if d.interfaces.length}
				<div class="card overflow-x-auto">
					<table class="w-full text-sm">
						<caption class="sr-only">Network interfaces</caption>
						<thead class="text-muted border-border border-b text-left text-xs">
							<tr><th class="px-3 py-2">Port</th><th class="px-3 py-2">Status</th><th class="hidden px-3 py-2 sm:table-cell">Speed</th><th class="px-3 py-2">Traffic in / out</th><th class="hidden px-3 py-2 lg:table-cell">Errors</th>{#if can('technician')}<th class="px-3 py-2">Alerts and history</th>{/if}</tr>
						</thead>
						<tbody class="divide-border divide-y">
							{#each d.interfaces as i (i.if_index)}
								<tr class={ifIndex === i.if_index ? 'bg-accent-soft' : ''}>
									<td class="px-3 py-2"><button class="hover:text-accent text-left font-medium" onclick={() => setParams({ port: ifIndex === i.if_index ? null : i.if_index })} aria-pressed={ifIndex === i.if_index}>{i.name || i.descr}</button>{#if i.alias}<div class="text-muted text-xs">{i.alias}</div>{/if}</td>
									<td class="px-3 py-2"><Badge tone={portTone(i)}>{portText(i)}</Badge></td>
									<td class="text-muted hidden px-3 py-2 whitespace-nowrap sm:table-cell">{i.speed_bps ? bps(i.speed_bps) : '–'}</td>
									<td class="tabular px-3 py-2 whitespace-nowrap">{bps(i.in_bps)} / {bps(i.out_bps)}{#if i.util_pct != null}<span class="text-muted"> · {i.util_pct.toFixed(0)}%</span>{/if}</td>
									<td class="text-muted tabular hidden px-3 py-2 lg:table-cell">{num(i.in_errors + i.out_errors)} errors, {num(i.in_discards + i.out_discards)} discards</td>
									{#if can('technician')}<td class="px-3 py-2"><Switch checked={i.monitored} onchange={(on) => monitorPort(i, on)} label="Monitor {i.name || i.descr}" /></td>{/if}
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				<p class="text-muted mt-2 text-xs">A port is monitored from the first time it's seen up, so unused ones don't alert or fill the database. Click a port's name for its traffic.</p>
			{:else}
				<div class="card"><EmptyState compact title="No ports read yet" description="The first reading lists them." /></div>
			{/if}
		</section>

		{#if chosen}
			<section class="mt-5" aria-label="Traffic of {chosen.name || chosen.descr}">
				<h3 class="mb-2 font-semibold">{chosen.name || chosen.descr} <span class="text-muted text-sm font-normal">{chosen.monitored ? '' : '· not monitored, no history is kept'}</span></h3>
				{#if inSeries.length > 1}
					<div class="grid gap-4 md:grid-cols-2">
						<div class="card p-4"><Chart label="Traffic in (Mbit/s)" points={inSeries} max={trafficMax} unit="" /></div>
						<div class="card p-4"><Chart label="Traffic out (Mbit/s)" points={outSeries} max={trafficMax} unit="" color="var(--chart-2)" /></div>
					</div>
				{:else}
					<div class="card"><EmptyState compact title="No traffic history yet" description={chosen.monitored ? 'It builds as the device is read.' : 'Monitor the port to keep its history.'} /></div>
				{/if}
			</section>
		{/if}

		{#if editing}
			<DeviceDialog device={d as never} onclose={() => (editing = false)} ondone={() => ((editing = false), device.reload())} />
		{/if}
	{/snippet}
</Async>
