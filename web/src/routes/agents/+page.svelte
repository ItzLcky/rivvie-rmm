<script lang="ts">
	import { page } from '$app/state';
	import { api, qs } from '#lib/api.js';
	import { ago, maxDiskPct, pct } from '#lib/format.js';
	import { can } from '#lib/session.svelte.js';
	import type { AgentSummary, Client } from '#lib/types.js';
	import Status from '#lib/components/Status.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';
	import RunScript from '#lib/components/RunScript.svelte';

	let agents = $state<AgentSummary[]>([]);
	let clients = $state<Client[]>([]);
	let q = $state('');
	let clientId = $state(page.url.searchParams.get('client_id') ?? '');
	let online = $state(page.url.searchParams.get('online') ?? '');
	let os = $state('');
	let selected = $state<Set<string>>(new Set());
	let running = $state(false);

	$effect(() => {
		api.get<Client[]>('/clients').then((c) => (clients = c));
	});

	$effect(() => {
		const query = qs({ q, client_id: clientId, online, os });
		const load = () => api.get<AgentSummary[]>(`/agents${query}`).then((a) => (agents = a));
		const debounce = setTimeout(load, 150);
		const t = setInterval(load, 15000);
		return () => {
			clearTimeout(debounce);
			clearInterval(t);
		};
	});

	const allSelected = $derived(agents.length > 0 && agents.every((a) => selected.has(a.id)));
	function toggleAll() {
		selected = allSelected ? new Set() : new Set(agents.map((a) => a.id));
	}
	function toggle(id: string) {
		const s = new Set(selected);
		if (s.has(id)) s.delete(id);
		else s.add(id);
		selected = s;
	}
</script>

<div class="mb-4 flex items-center justify-between">
	<h1 class="text-xl font-semibold">Agents <span class="text-base font-normal text-slate-500">{agents.length}</span></h1>
	{#if can('technician')}
		<button class="btn-primary" disabled={!selected.size} onclick={() => (running = true)}>Run script on {selected.size || ''} selected</button>
	{/if}
</div>

<div class="mb-4 flex flex-wrap gap-2">
	<input class="input max-w-xs" placeholder="Search hostname…" bind:value={q} />
	<select class="input max-w-48" bind:value={clientId}>
		<option value="">All clients</option>
		{#each clients as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
	</select>
	<select class="input max-w-36" bind:value={online}>
		<option value="">Any status</option><option value="true">Online</option><option value="false">Offline</option>
	</select>
	<select class="input max-w-36" bind:value={os}>
		<option value="">Any OS</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option>
	</select>
</div>

<div class="card overflow-x-auto">
	<table class="table">
		<thead>
			<tr>
				<th class="w-8"><input type="checkbox" checked={allSelected} onchange={toggleAll} aria-label="Select all" /></th>
				<th>Hostname</th><th>Client / Site</th><th>OS</th><th>Status</th><th class="w-32">CPU</th><th class="w-32">Memory</th><th class="w-32">Disk</th><th>Last seen</th>
			</tr>
		</thead>
		<tbody>
			{#each agents as a (a.id)}
				{@const m = a.last_metrics}
				<tr>
					<td><input type="checkbox" checked={selected.has(a.id)} onchange={() => toggle(a.id)} aria-label="Select {a.hostname}" /></td>
					<td><a class="font-medium text-sky-400 hover:underline" href="/agents/{a.id}">{a.hostname}</a></td>
					<td class="text-slate-400">{a.client_name} <span class="text-slate-600">/</span> {a.site_name}</td>
					<td><OsBadge os={a.os_family} /> <span class="ml-1 text-xs text-slate-500">{a.os_name}</span></td>
					<td><Status online={a.online} /></td>
					<td>{#if m && a.online}<UsageBar value={m.cpu_percent} />{:else}<span class="text-slate-600">–</span>{/if}</td>
					<td>{#if m}<UsageBar value={pct(m.mem_used, m.mem_total)} />{:else}<span class="text-slate-600">–</span>{/if}</td>
					<td>{#if m}<UsageBar value={maxDiskPct(m)} />{:else}<span class="text-slate-600">–</span>{/if}</td>
					<td class="text-xs text-slate-400">{a.online ? 'now' : ago(a.last_seen_at)}</td>
				</tr>
			{:else}
				<tr><td colspan="9" class="py-8 text-center text-slate-500">No agents match.</td></tr>
			{/each}
		</tbody>
	</table>
</div>

{#if running}
	<RunScript agents={agents.filter((a) => selected.has(a.id))} onclose={() => (running = false)} />
{/if}
