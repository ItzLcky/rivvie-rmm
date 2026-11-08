<script lang="ts">
	import type { Component } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import { cx } from '#lib/format.js';
	import Tooltip from './Tooltip.svelte';
	import { buttonBase, buttonVariants, type ButtonVariant } from './Button.svelte';

	/** An icon-only button. `label` is required: it's the accessible name and the tooltip. */
	type Props = HTMLButtonAttributes & {
		icon: Component<{ class?: string }>;
		label: string;
		variant?: ButtonVariant;
		size?: 'sm' | 'md';
		href?: string;
		tooltip?: boolean;
		active?: boolean;
	};
	let { icon: Icon, label, variant = 'ghost', size = 'md', href, tooltip = true, active = false, class: klass, type = 'button', ...rest }: Props = $props();
	const cls = $derived(
		cx(buttonBase, buttonVariants[variant], size === 'sm' ? 'size-7 [&_svg]:size-4' : 'size-8 [&_svg]:size-[18px]', active && 'bg-hover text-fg', klass as string)
	);
</script>

<Tooltip text={label} disabled={!tooltip}>
	{#snippet trigger(props)}
		{#if href}
			<a {...props} {href} class={cls} aria-label={label}><Icon /></a>
		{:else}
			<button {...props} {...rest} {type} class={cls} aria-label={label} aria-pressed={active || undefined}><Icon /></button>
		{/if}
	{/snippet}
</Tooltip>
