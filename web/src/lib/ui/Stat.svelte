<script lang="ts">
	import { cx, num } from '#lib/format.js';

	/**
	 * The one KPI tile: a label and a number, no decoration. The number is neutral at 0 and only
	 * takes `tone` when it's non-zero, so colour means "look here". Pass `href` and the tile is a
	 * link to the matching filtered list.
	 */
	let {
		label,
		value,
		of,
		tone,
		href,
		capped = false
	}: { label: string; value: number; of?: number; tone?: 'warning' | 'danger'; href?: string; capped?: boolean } = $props();
	const color = $derived(value > 0 && tone ? (tone === 'danger' ? 'text-danger' : 'text-warning') : 'text-fg');
</script>

<svelte:element this={href ? 'a' : 'div'} {href} class={cx('card block min-w-0 p-3', href && 'hover:border-border-strong transition-colors')}>
	<div class="text-muted text-xs font-medium">{label}</div>
	<div class={cx('mt-1 text-2xl leading-none font-semibold tabular', color)}>
		{num(value)}{capped ? '+' : ''}{#if of !== undefined}<span class="text-muted ml-1 text-sm font-normal">of {num(of)}</span>{/if}
	</div>
</svelte:element>
