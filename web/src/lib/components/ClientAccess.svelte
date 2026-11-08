<script lang="ts">
	import type { Client } from '#lib/types.js';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/** Which clients a non-admin user can see. Admins always see every client. */
	let { clients, value = $bindable() }: { clients: Client[]; value: { all_clients: boolean; client_ids: string[] } } = $props();

	function toggle(id: string, on: boolean) {
		value.client_ids = on ? [...value.client_ids, id] : value.client_ids.filter((c) => c !== id);
	}
</script>

<div class="space-y-3">
	<Switch bind:checked={value.all_clients}>All clients, including ones added later</Switch>
	{#if !value.all_clients}
		<div class="border-border max-h-56 space-y-2 overflow-y-auto rounded-md border p-3">
			{#each clients as c (c.id)}
				<div><Checkbox checked={value.client_ids.includes(c.id)} onchange={(on) => toggle(c.id, on)}>{c.name}</Checkbox></div>
			{:else}
				<p class="text-muted text-sm">No clients yet.</p>
			{/each}
		</div>
		{#if value.client_ids.length === 0}<p class="text-warning text-xs">With no clients selected, this user sees no agents at all.</p>{/if}
	{/if}
</div>
