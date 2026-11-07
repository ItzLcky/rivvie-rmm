<script lang="ts">
	import { api } from '#lib/api.js';
	import { maxDiskPct } from '#lib/format.js';
	import type { Dashboard } from '#lib/types.js';
	import UsageBar from '#lib/components/UsageBar.svelte';
	import Status from '#lib/components/Status.svelte';

	let d = $state<Dashboard | null>(null);

	$effect(() => {
		const load = () => api.get<Dashboard>('/dashboard').then((r) => (d = r));
		load();
		const t = setInterval(load, 15000);
		return () => clearInterval(t);
	});

	const jobsTotal = $derived(d ? Object.values(d.jobs_24h).reduce((a, b) => a + b, 0) : 0);
	const jobsBad = $derived(d ? (d.jobs_24h.failed ?? 0) + (d.jobs_24h.error ?? 0) + (d.jobs_24h.timed_out ?? 0) : 0);
</script>

<h1 class="mb-6 text-xl font-semibold">Dashboard</h1>

{#if d}
	<div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
		<a href="/agents" class="card p-4 hover:border-slate-700">
			<div class="label">Agents online</div>
			<div class="text-2xl font-semibold tabular-nums">{d.agents_online}<span class="text-base text-slate-500"> / {d.agents_total}</span></div>
		</a>
		<a href="/agents?online=false" class="card p-4 hover:border-slate-700">
			<div class="label">Offline</div>
			<div class="text-2xl font-semibold tabular-nums {d.agents_total - d.agents_online ? 'text-amber-400' : ''}">{d.agents_total - d.agents_online}</div>
		</a>
		<a href="/clients" class="card p-4 hover:border-slate-700">
			<div class="label">Clients</div>
			<div class="text-2xl font-semibold tabular-nums">{d.clients}</div>
		</a>
		<a href="/jobs" class="card p-4 hover:border-slate-700">
			<div class="label">Jobs (24h)</div>
			<div class="text-2xl font-semibold tabular-nums">{jobsTotal}{#if jobsBad}<span class="ml-2 text-base text-red-400">{jobsBad} failed</span>{/if}</div>
		</a>
	</div>

	<div class="mt-6 grid gap-4 lg:grid-cols-3">
		<div class="card p-4">
			<h2 class="mb-3 text-sm font-semibold">Operating systems</h2>
			{#each Object.entries(d.by_os) as [os, n] (os)}
				<div class="flex justify-between py-1 text-sm"><span class="capitalize">{os}</span><span class="tabular-nums text-slate-400">{n}</span></div>
			{:else}
				<p class="text-sm text-slate-500">No agents enrolled yet. <a class="text-sky-400" href="/clients">Create an enrollment token</a>.</p>
			{/each}
		</div>
		<div class="card p-4 lg:col-span-2">
			<h2 class="mb-3 text-sm font-semibold">Disks over 90% full</h2>
			{#if d.high_disk.length}
				<table class="table">
					<tbody>
						{#each d.high_disk as a (a.id)}
							<tr>
								<td><a class="text-sky-400 hover:underline" href="/agents/{a.id}">{a.hostname}</a></td>
								<td class="text-slate-400">{a.client_name}</td>
								<td><Status online={a.online} /></td>
								<td class="w-48"><UsageBar value={maxDiskPct(a.last_metrics)} /></td>
							</tr>
						{/each}
					</tbody>
				</table>
			{:else}
				<p class="text-sm text-slate-500">All disks healthy.</p>
			{/if}
		</div>
	</div>
{/if}
