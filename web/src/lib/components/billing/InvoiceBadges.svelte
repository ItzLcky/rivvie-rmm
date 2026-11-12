<script lang="ts">
	import { statusLabels, statusTones } from '#lib/billing/meta.js';
	import type { Invoice } from '#lib/billing/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** Status, credit note and overdue badges for an invoice. */
	let { invoice: i }: { invoice: Pick<Invoice, 'status' | 'kind' | 'overdue'> } = $props();
</script>

<span class="inline-flex flex-wrap items-center gap-1">
	<Badge tone={statusTones[i.status]} dot>{statusLabels[i.status]}</Badge>
	{#if i.kind === 'credit_note'}<Badge tone="info">Credit note</Badge>{/if}
	{#if i.overdue}<Badge tone="danger">Overdue</Badge>{/if}
</span>
