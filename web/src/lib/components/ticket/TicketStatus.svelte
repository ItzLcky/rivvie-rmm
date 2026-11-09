<script lang="ts">
	import { categoryOf } from '#lib/servicedesk/tickets.svelte.js';
	import type { StatusCategory } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** The board's status name, coloured by its category. */
	let { name, category }: { name: string; category: StatusCategory } = $props();
	const c = $derived(categoryOf(category));
</script>

<Badge tone={c.tone} title={c.label}>{name}</Badge>
