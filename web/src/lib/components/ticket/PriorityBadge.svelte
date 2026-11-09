<script lang="ts">
	import { priorityOf } from '#lib/servicedesk/tickets.svelte.js';
	import type { Priority } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	let { priority, long = false }: { priority: Priority; long?: boolean } = $props();
	const p = $derived(priorityOf(priority));
</script>

<Badge tone={p.tone} dot={priority <= 2} title={p.label}>{long ? p.label : p.short}</Badge>
