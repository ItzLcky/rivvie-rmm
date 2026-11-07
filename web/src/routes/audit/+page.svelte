<script lang="ts">
	import { api } from '#lib/api.js';
	import { datetime } from '#lib/format.js';

	interface Row { id: number; ts: string; user_name: string | null; action: string; target_type: string | null; target_id: string | null; details: Record<string, unknown> }
	let rows = $state<Row[]>([]);
	$effect(() => {
		api.get<Row[]>('/audit').then((r) => (rows = r));
	});
</script>

<h1 class="mb-4 text-xl font-semibold">Audit log</h1>
<div class="card overflow-x-auto">
	<table class="table">
		<thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
		<tbody>
			{#each rows as r (r.id)}
				<tr>
					<td class="text-xs whitespace-nowrap text-slate-400">{datetime(r.ts)}</td>
					<td>{r.user_name ?? 'system'}</td>
					<td class="font-mono text-xs">{r.action}</td>
					<td class="text-xs text-slate-400">
						{#if r.target_type === 'agent' && r.target_id}<a class="text-sky-400 hover:underline" href="/agents/{r.target_id}">agent</a>{:else}{r.target_type ?? ''}{/if}
					</td>
					<td class="font-mono text-xs text-slate-500">{Object.keys(r.details).length ? JSON.stringify(r.details) : ''}</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>
