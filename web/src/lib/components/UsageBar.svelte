<script lang="ts">
	import { cx } from '#lib/format.js';

	/**
	 * A usage percentage. In tables use `bar={false}`: a right-aligned tabular number that only
	 * takes colour past 75% (warning) and 90% (danger, bold), so the eye lands on the outliers.
	 * The bar is for places that show one entity at a time (a detail page, the fullest disks).
	 */
	let { value, label = '', bar = true }: { value: number; label?: string; bar?: boolean } = $props();
	const v = $derived(Math.min(100, Math.max(0, value)));
	const color = $derived(v >= 90 ? 'bg-danger' : v >= 75 ? 'bg-warning' : 'bg-accent');
	const text = $derived(v >= 90 ? 'text-danger font-medium' : v >= 75 ? 'text-warning font-medium' : bar ? 'text-muted' : 'text-fg');
</script>

{#if bar}
	<div class="flex items-center gap-2" title={label || undefined}>
		<div class="bg-sunken border-border h-1.5 w-full min-w-12 overflow-hidden rounded-full border" role="meter" aria-valuenow={Math.round(v)} aria-valuemin={0} aria-valuemax={100} aria-label={label || `${v.toFixed(0)}%`}>
			<div class={cx('h-full rounded-full', color)} style="width: {v}%"></div>
		</div>
		<span class={cx('w-9 shrink-0 text-right text-xs tabular', text)}>{v.toFixed(0)}%</span>
	</div>
{:else}
	<span class={cx('tabular', text)} title={label || undefined}>{v.toFixed(0)}%</span>
{/if}
