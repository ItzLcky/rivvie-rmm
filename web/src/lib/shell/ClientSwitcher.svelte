<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { clientId, clients, SCOPED_PAGES, withClient } from '#lib/scope.svelte.js';
	import { setParams } from '#lib/url.svelte.js';
	import Combobox from '#lib/ui/Combobox.svelte';

	const ALL = '__all';
	const items = $derived([{ value: ALL, label: 'All clients' }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]);
	let value = $state(ALL);
	$effect(() => {
		value = clientId() || ALL;
	});

	function pick(v: string) {
		const id = v === ALL || !v ? '' : v;
		if (SCOPED_PAGES.includes(page.url.pathname)) setParams({ client: id || null });
		else goto(withClient('/', id));
	}
</script>

{#if clients.list.length > 1}
	<Combobox bind:value {items} label="Client" placeholder="All clients" onchange={pick} class="w-36 sm:w-52" />
{/if}
