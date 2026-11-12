<script lang="ts">
	import type { Alert } from '#lib/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	let { alert }: { alert: Pick<Alert, 'state' | 'resolution' | 'acknowledged_by_name'> & Partial<Pick<Alert, 'suppressed'>> } = $props();
	const resolved: Record<string, string> = { cleared: 'Cleared', manual: 'Resolved', policy: 'Closed' };
</script>

<span class="inline-flex flex-wrap items-center gap-1">
	{#if alert.state === 'open'}
		<Badge tone="danger" dot>Open</Badge>
	{:else if alert.state === 'acknowledged'}
		<Badge tone="info" title={alert.acknowledged_by_name ? `Acknowledged by ${alert.acknowledged_by_name}` : undefined}>Acknowledged</Badge>
	{:else}
		<Badge tone="success">{resolved[alert.resolution ?? ''] ?? 'Resolved'}</Badge>
	{/if}
	{#if alert.suppressed && alert.state !== 'resolved'}
		<Badge tone="neutral" title="Opened during a maintenance window or snooze: nobody has been notified, and no ticket opened. If it's still open when the window ends, it's announced then.">Muted</Badge>
	{/if}
</span>
