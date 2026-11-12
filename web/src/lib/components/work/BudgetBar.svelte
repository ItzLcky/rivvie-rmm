<script lang="ts">
	import { cx } from '#lib/format.js';
	import { fmtMinutes } from '#lib/work/time.js';

	/** Logged time against a budget, with the numbers in text so colour isn't the only signal. */
	let { logged, budget, compact = false }: { logged: number; budget: number; compact?: boolean } = $props();
	const pct = $derived(budget > 0 ? (logged / budget) * 100 : 0);
	const over = $derived(budget > 0 && logged > budget);
	const fill = $derived(over ? 'bg-danger' : pct >= 80 ? 'bg-warning' : 'bg-accent');
</script>

<div class={cx('min-w-0', compact ? 'w-full' : '')}>
	{#if budget > 0}
		<div class="bg-sunken border-border h-2 overflow-hidden rounded-full border" aria-hidden="true">
			<div class={cx('h-full rounded-full', fill)} style="width: {Math.min(100, pct)}%"></div>
		</div>
		<p class={cx('mt-1 text-xs tabular', over ? 'text-danger font-medium' : 'text-muted')}>
			{fmtMinutes(logged)} of {fmtMinutes(budget)} · {Math.round(pct)}%{over ? ' (over budget)' : ''}
		</p>
	{:else}
		<p class="text-muted text-xs tabular">{fmtMinutes(logged)} logged · no budget</p>
	{/if}
</div>
