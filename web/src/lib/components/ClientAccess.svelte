<script lang="ts">
	import type { Client } from '#lib/types.js';

	/** Which clients a non-admin user can see. Admins always see every client. */
	let { clients, value = $bindable() }: { clients: Client[]; value: { all_clients: boolean; client_ids: string[] } } = $props();

	function toggle(id: string, on: boolean) {
		value.client_ids = on ? [...value.client_ids, id] : value.client_ids.filter((c) => c !== id);
	}
</script>

<div class="space-y-2">
	<label class="flex items-center gap-2 text-sm">
		<input type="checkbox" bind:checked={value.all_clients} />
		All clients, including ones added later
	</label>
	{#if !value.all_clients}
		<div class="max-h-56 space-y-1 overflow-y-auto rounded-md border border-slate-800 p-2">
			{#each clients as c (c.id)}
				<label class="flex items-center gap-2 text-sm">
					<input type="checkbox" checked={value.client_ids.includes(c.id)} onchange={(e) => toggle(c.id, e.currentTarget.checked)} />
					{c.name}
				</label>
			{:else}
				<p class="text-sm text-slate-500">No clients yet.</p>
			{/each}
		</div>
		{#if value.client_ids.length === 0}<p class="text-xs text-amber-300">With no clients selected, this user sees no agents at all.</p>{/if}
	{/if}
</div>
