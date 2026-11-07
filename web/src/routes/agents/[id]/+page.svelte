<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { ago, bytes, datetime, duration, pct } from '#lib/format.js';
	import { can } from '#lib/session.svelte.js';
	import type { AgentDetail, Job, MetricPoint } from '#lib/types.js';
	import Status from '#lib/components/Status.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';
	import Chart from '#lib/components/Chart.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';
	import RunScript from '#lib/components/RunScript.svelte';
	import Terminal from '#lib/components/Terminal.svelte';

	const id = $derived(page.params.id!);
	type Tab = 'overview' | 'software' | 'hardware' | 'jobs' | 'terminal';
	let tab = $state<Tab>('overview');
	let agent = $state<AgentDetail | null>(null);
	let history = $state<MetricPoint[]>([]);
	let jobs = $state<Job[]>([]);
	let hours = $state(24);
	let swq = $state('');
	let running = $state(false);
	let notice = $state('');

	$effect(() => {
		const load = () => api.get<AgentDetail>(`/agents/${id}`).then((a) => (agent = a));
		load();
		const t = setInterval(load, 10000);
		return () => clearInterval(t);
	});
	$effect(() => {
		api.get<MetricPoint[]>(`/agents/${id}/metrics?hours=${hours}`).then((m) => (history = m));
	});
	$effect(() => {
		if (tab === 'jobs') api.get<Job[]>(`/agents/${id}/jobs`).then((j) => (jobs = j));
	});

	const m = $derived(agent?.last_metrics);
	const inv = $derived(agent?.inventory);
	const software = $derived(
		(inv?.software ?? []).filter((s) => !swq || `${s.name} ${s.publisher ?? ''}`.toLowerCase().includes(swq.toLowerCase()))
	);
	const cpuSeries = $derived(history.map((p) => ({ t: Date.parse(p.ts), v: p.cpu_percent })));
	const memSeries = $derived(history.map((p) => ({ t: Date.parse(p.ts), v: pct(p.mem_used, p.mem_total) })));

	async function refreshInventory() {
		try {
			await api.post(`/agents/${id}/inventory/refresh`);
			notice = 'Inventory refresh requested; it will update shortly.';
		} catch (e) {
			notice = (e as Error).message;
		}
	}
	async function remove() {
		if (!agent || !confirm(`Remove ${agent.hostname}? The agent will be disconnected and must be re-enrolled.`)) return;
		await api.del(`/agents/${id}`);
		await goto('/agents');
	}
</script>

{#if agent}
	<div class="mb-1 text-sm text-slate-500"><a href="/agents" class="hover:text-slate-300">Agents</a> / {agent.client_name} / {agent.site_name}</div>
	<div class="mb-4 flex flex-wrap items-center justify-between gap-3">
		<div class="flex items-center gap-3">
			<h1 class="text-xl font-semibold">{agent.hostname}</h1>
			<OsBadge os={agent.os_family} />
			<Status online={agent.online} />
		</div>
		<div class="flex gap-2">
			{#if can('technician')}
				<button class="btn-ghost" disabled={!agent.online} onclick={() => (tab = 'terminal')}>Terminal</button>
				<button class="btn-primary" onclick={() => (running = true)}>Run script</button>
			{/if}
			{#if can('admin')}<button class="btn-danger" onclick={remove}>Remove</button>{/if}
		</div>
	</div>

	<div class="mb-4 flex gap-1 border-b border-slate-800">
		{#each [['overview', 'Overview'], ['software', `Software (${inv?.software.length ?? 0})`], ['hardware', 'Hardware & network'], ['jobs', 'Jobs'], ['terminal', 'Terminal']] as [k, label] (k)}
			{#if k !== 'terminal' || can('technician')}
				<button class="tab {tab === k ? 'tab-active' : ''}" onclick={() => (tab = k as Tab)}>{label}</button>
			{/if}
		{/each}
	</div>

	{#if notice}<p class="mb-3 text-sm text-sky-300">{notice}</p>{/if}

	{#if tab === 'overview'}
		<div class="grid gap-4 lg:grid-cols-3">
			<div class="card p-4">
				<h2 class="mb-3 text-sm font-semibold">System</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
					<dt class="text-slate-500">OS</dt><dd>{agent.os_version || agent.os_name}</dd>
					<dt class="text-slate-500">Kernel</dt><dd>{agent.kernel_version}</dd>
					<dt class="text-slate-500">Arch</dt><dd>{agent.arch}</dd>
					<dt class="text-slate-500">CPU</dt><dd>{inv?.cpu_brand ?? '–'}{#if inv}{' '}({inv.cpu_cores_physical ?? '?'}C/{inv.cpu_cores_logical}T){/if}</dd>
					<dt class="text-slate-500">Memory</dt><dd>{bytes(inv?.mem_total ?? m?.mem_total)}</dd>
					<dt class="text-slate-500">Uptime</dt><dd>{m ? duration(m.uptime_secs) : '–'}</dd>
					<dt class="text-slate-500">Users</dt><dd>{inv?.logged_in_users.join(', ') || '–'}</dd>
					<dt class="text-slate-500">Agent</dt><dd>v{agent.agent_version}</dd>
					<dt class="text-slate-500">Last seen</dt><dd>{agent.online ? 'now' : ago(agent.last_seen_at)}</dd>
					<dt class="text-slate-500">Enrolled</dt><dd>{datetime(agent.enrolled_at)}</dd>
				</dl>
			</div>
			<div class="card p-4 lg:col-span-2">
				<div class="mb-3 flex items-center justify-between">
					<h2 class="text-sm font-semibold">Live</h2>
					<select class="input w-auto py-0.5 text-xs" bind:value={hours}>
						<option value={1}>1 hour</option><option value={24}>24 hours</option><option value={168}>7 days</option><option value={720}>30 days</option>
					</select>
				</div>
				{#if m}
					<div class="mb-4 grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
						<div><div class="label">CPU</div><UsageBar value={m.cpu_percent} /></div>
						<div><div class="label">Memory</div><UsageBar value={pct(m.mem_used, m.mem_total)} label="{bytes(m.mem_used)} / {bytes(m.mem_total)}" /></div>
						<div><div class="label">Swap</div><UsageBar value={pct(m.swap_used, m.swap_total)} /></div>
						<div><div class="label">Load / procs</div><span class="tabular-nums">{m.load_avg ? m.load_avg.map((l) => l.toFixed(2)).join(' ') : '–'} · {m.process_count}</span></div>
					</div>
				{/if}
				<div class="label">CPU %</div>
				<Chart points={cpuSeries} />
				<div class="label mt-3">Memory %</div>
				<Chart points={memSeries} color="#a78bfa" />
			</div>
			<div class="card p-4 lg:col-span-3">
				<h2 class="mb-3 text-sm font-semibold">Volumes</h2>
				<table class="table">
					<thead><tr><th>Mount</th><th>Size</th><th>Free</th><th class="w-64">Used</th></tr></thead>
					<tbody>
						{#each m?.disks ?? [] as d (d.mount)}
							<tr><td class="font-mono text-xs">{d.mount}</td><td>{bytes(d.total)}</td><td>{bytes(d.available)}</td><td><UsageBar value={pct(d.total - d.available, d.total)} /></td></tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{:else if tab === 'software'}
		<div class="mb-3 flex items-center gap-3">
			<input class="input max-w-sm" placeholder="Filter software…" bind:value={swq} />
			<span class="text-xs text-slate-500">Collected {ago(agent.inventory_at)}</span>
			{#if can('technician')}<button class="btn-ghost ml-auto" disabled={!agent.online} onclick={refreshInventory}>Refresh inventory</button>{/if}
		</div>
		<div class="card overflow-x-auto">
			<table class="table">
				<thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Source</th></tr></thead>
				<tbody>
					{#each software.slice(0, 1000) as s (s.source + s.name + s.version)}
						<tr><td>{s.name}</td><td class="font-mono text-xs">{s.version}</td><td class="text-slate-400">{s.publisher ?? ''}</td><td class="text-xs text-slate-500">{s.source}</td></tr>
					{/each}
				</tbody>
			</table>
			{#if software.length > 1000}<p class="p-3 text-xs text-slate-500">Showing 1000 of {software.length}; refine the filter.</p>{/if}
		</div>
	{:else if tab === 'hardware'}
		<div class="grid gap-4 lg:grid-cols-2">
			<div class="card p-4">
				<h2 class="mb-3 text-sm font-semibold">Disks</h2>
				<table class="table">
					<thead><tr><th>Device</th><th>Mount</th><th>FS</th><th>Type</th><th>Size</th></tr></thead>
					<tbody>
						{#each inv?.disks ?? [] as d (d.mount)}
							<tr><td class="font-mono text-xs">{d.name}</td><td class="font-mono text-xs">{d.mount}</td><td>{d.fs}</td><td>{d.kind}{d.removable ? ' (removable)' : ''}</td><td>{bytes(d.total)}</td></tr>
						{/each}
					</tbody>
				</table>
			</div>
			<div class="card p-4">
				<h2 class="mb-3 text-sm font-semibold">Network interfaces</h2>
				<table class="table">
					<thead><tr><th>Name</th><th>MAC</th><th>Addresses</th></tr></thead>
					<tbody>
						{#each inv?.network ?? [] as n (n.name)}
							<tr><td>{n.name}</td><td class="font-mono text-xs">{n.mac}</td><td class="font-mono text-xs">{n.addrs.join(', ')}</td></tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{:else if tab === 'jobs'}
		<div class="card overflow-x-auto">
			<table class="table">
				<thead><tr><th>Started</th><th>Script</th><th>Status</th><th>Exit</th><th>Duration</th><th>By</th></tr></thead>
				<tbody>
					{#each jobs as j (j.id)}
						<tr>
							<td><a class="text-sky-400 hover:underline" href="/jobs/{j.id}">{datetime(j.created_at)}</a></td>
							<td>{j.script_name ?? `ad-hoc ${j.interpreter}`}</td>
							<td><JobBadge status={j.status} /></td>
							<td class="tabular-nums">{j.exit_code ?? ''}</td>
							<td class="tabular-nums">{j.duration_ms != null ? `${(j.duration_ms / 1000).toFixed(1)}s` : ''}</td>
							<td class="text-slate-400">{j.created_by_name ?? ''}</td>
						</tr>
					{:else}
						<tr><td colspan="6" class="py-6 text-center text-slate-500">No jobs yet.</td></tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else if tab === 'terminal'}
		{#if agent.online}
			<Terminal agentId={agent.id} />
		{:else}
			<p class="text-slate-500">The agent is offline.</p>
		{/if}
	{/if}

	{#if running}<RunScript agents={[agent]} onclose={() => (running = false)} />{/if}
{/if}
