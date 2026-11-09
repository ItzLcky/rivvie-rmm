<script lang="ts">
	import type { Alert } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	let { alert }: { alert: Pick<Alert, 'state' | 'resolution' | 'acknowledged_by_name'> } = $props();
	const resolved: Record<string, string> = { cleared: 'Cleared', manual: 'Resolved', policy: 'Closed' };
</script>

{#if alert.state === 'open'}
	<Badge tone="danger" dot>Open</Badge>
{:else if alert.state === 'acknowledged'}
	<Badge tone="info" title={alert.acknowledged_by_name ? `Acknowledged by ${alert.acknowledged_by_name}` : undefined}>Acknowledged</Badge>
{:else}
	<Badge tone="success">{resolved[alert.resolution ?? ''] ?? 'Resolved'}</Badge>
{/if}
