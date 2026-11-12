<script lang="ts">
	import { balanceTone, cycleLabel, kindLabel, perCycle } from '#lib/billing/meta.js';
	import { formatHours, formatMoney } from '#lib/billing/money.js';
	import type { Contract } from '#lib/billing/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/** One line on what a contract charges, and its block-hours balance. */
	let { contract: c, currency }: { contract: Contract; currency: string } = $props();
	const per = $derived(perCycle(c.billing_cycle));
	const price = $derived(currency ? formatMoney(c.unit_price, currency) : '');
	const text = $derived(
		{
			per_device: `${price} per device a ${per}${c.device_filter !== 'all' ? ` (${c.device_filter})` : ''}`,
			per_user: `${price} per user a ${per} · ${c.user_count} users`,
			block_hours: `${formatHours(c.block_minutes)} for ${price} a ${per}`,
			recurring: `${price} a ${per}`,
			time_materials: 'Time & materials'
		}[c.kind]
	);
</script>

<span class="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
	<span>{kindLabel(c.kind)}{#if c.kind !== 'time_materials'}<span class="text-muted"> · {currency ? text : cycleLabel(c.billing_cycle)}</span>{/if}</span>
	{#if c.kind === 'block_hours'}
		<Badge tone={balanceTone(c)} title="Hours left in the bank">{formatHours(c.balance_minutes ?? 0)} left</Badge>
	{/if}
</span>
