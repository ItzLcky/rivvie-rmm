<script lang="ts">
	import { Timer } from '@lucide/svelte';
	import { slaState } from '#lib/servicedesk/sla.js';
	import type { Ticket } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	let { ticket }: { ticket: Ticket } = $props();
	const s = $derived(slaState(ticket));
</script>

{#if s}<Badge tone={s.tone} icon={Timer} title={s.title}>{s.label}</Badge>{/if}
