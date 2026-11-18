<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { itemHref } from '#lib/policy/policy.js';
	import type { ItemView } from '#lib/policy/types.js';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	// Alerts and jobs know only the policy's id: open it in the set it's defined in.
	let error = $state<Error | null>(null);
	$effect(() => {
		const id = page.params.id!;
		error = null;
		api.get<ItemView>(`/policy-items/${id}`).then(
			(v) => goto(itemHref(v.origin_set_id, v), { replace: true }),
			(e) => (error = e)
		);
	});
</script>

<svelte:head><title>Policy</title></svelte:head>

{#if error}
	<h1 class="sr-only">Policy</h1>
	<div class="card"><ErrorState {error} onretry={() => goto(page.url.pathname, { replace: true })} /></div>
{:else}
	<div class="space-y-2" aria-busy="true"><Skeleton class="h-3 w-48" /><Skeleton class="h-7 w-64" /></div>
{/if}
