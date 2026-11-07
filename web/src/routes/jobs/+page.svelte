<script lang="ts">
	import { api } from '#lib/api.js';
	import { datetime } from '#lib/format.js';
	import type { Job } from '#lib/types.js';
	import JobBadge from '#lib/components/JobBadge.svelte';

	let jobs = $state<Job[]>([]);
	$effect(() => {
		const load = () => api.get<Job[]>('/jobs').then((j) => (jobs = j));
		load();
		const t = setInterval(load, 5000);
		return () => clearInterval(t);
	});
</script>

<h1 class="mb-4 text-xl font-semibold">Job history</h1>
<div class="card overflow-x-auto">
	<table class="table">
		<thead><tr><th>Created</th><th>Agent</th><th>Script</th><th>Status</th><th>Exit</th><th>Duration</th><th>By</th></tr></thead>
		<tbody>
			{#each jobs as j (j.id)}
				<tr>
					<td><a class="text-sky-400 hover:underline" href="/jobs/{j.id}">{datetime(j.created_at)}</a></td>
					<td><a class="hover:text-sky-400" href="/agents/{j.agent_id}">{j.hostname}</a></td>
					<td>{j.script_name ?? `ad-hoc ${j.interpreter}`}</td>
					<td><JobBadge status={j.status} /></td>
					<td class="tabular-nums">{j.exit_code ?? ''}</td>
					<td class="tabular-nums">{j.duration_ms != null ? `${(j.duration_ms / 1000).toFixed(1)}s` : ''}</td>
					<td class="text-slate-400">{j.created_by_name ?? ''}</td>
				</tr>
			{:else}
				<tr><td colspan="7" class="py-8 text-center text-slate-500">No jobs yet.</td></tr>
			{/each}
		</tbody>
	</table>
</div>
