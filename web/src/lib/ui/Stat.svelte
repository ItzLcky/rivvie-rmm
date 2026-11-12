<script lang="ts">
	import type { Component } from 'svelte';
	import { cx, num } from '#lib/format.js';

	/**
	 * The one KPI tile: a label, a number and an optional icon. The number is neutral at 0 and
	 * only takes `tone` when it's non-zero, so colour means "look here"; the icon chip follows
	 * the same rule. Pass `href` and the tile is a link to the matching filtered list.
	 */
	let {
		label,
		value,
		of,
		tone,
		href,
		icon: Icon,
		capped = false
	}: {
		label: string;
		value: number;
		of?: number;
		tone?: 'warning' | 'danger';
		href?: string;
		icon?: Component<{ class?: string }>;
		capped?: boolean;
	} = $props();
	const hot = $derived(value > 0 && !!tone);
	const color = $derived(hot ? (tone === 'danger' ? 'text-danger' : 'text-warning') : 'text-fg');
	const chip = $derived(hot ? (tone === 'danger' ? 'bg-danger-soft text-danger' : 'bg-warning-soft text-warning') : 'bg-sunken text-muted');
</script>

<svelte:element
	this={href ? 'a' : 'div'}
	{href}
	class={cx('card group block min-w-0 p-4', href && 'hover:border-border-strong transition-[border-color,box-shadow] duration-150 hover:shadow-[var(--shadow-lg)]')}
>
	<div class="flex items-start justify-between gap-3">
		<div class="text-muted min-w-0 truncate text-[0.8125rem] font-medium">{label}</div>
		{#if Icon}
			<span class={cx('flex size-8 shrink-0 items-center justify-center rounded-md transition-colors', chip)} aria-hidden="true"><Icon class="size-4" /></span>
		{/if}
	</div>
	<div class={cx('text-[1.75rem] leading-none font-semibold tracking-tight tabular', Icon ? '-mt-1' : 'mt-2', color)}>
		{num(value)}{capped ? '+' : ''}{#if of !== undefined}<span class="text-muted ml-1.5 text-sm font-normal tracking-normal">of {num(of)}</span>{/if}
	</div>
</svelte:element>
