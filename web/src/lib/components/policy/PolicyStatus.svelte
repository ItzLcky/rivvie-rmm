<script lang="ts">
	import { CircleDot, CornerLeftUp, PencilLine } from '@lucide/svelte';
	import type { ItemView } from '#lib/policy/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** Where a policy comes from in the set being viewed. Icon and text, never colour alone. */
	let { view, short = false }: { view: Pick<ItemView, 'status' | 'origin_set_name'>; short?: boolean } = $props();
</script>

{#if view.status === 'defined'}
	<Badge tone="accent" icon={CircleDot}>Defined here</Badge>
{:else if view.status === 'overridden'}
	<Badge tone="info" icon={PencilLine} title="Defined in {view.origin_set_name}, with fields changed in this set">Overridden here</Badge>
{:else}
	<Badge icon={CornerLeftUp} title="Defined in {view.origin_set_name}">{short ? 'Inherited' : `Inherited from ${view.origin_set_name}`}</Badge>
{/if}
