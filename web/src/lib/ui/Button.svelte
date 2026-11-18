<script lang="ts" module>
	export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-ghost';
	export type ButtonSize = 'xs' | 'sm' | 'md';
	export const buttonBase =
		'inline-flex shrink-0 cursor-pointer items-center justify-center gap-1.5 rounded-md font-semibold whitespace-nowrap transition-[background-color,border-color,color,box-shadow,transform] duration-150 select-none active:translate-y-px disabled:cursor-not-allowed disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50';
	export const buttonVariants: Record<ButtonVariant, string> = {
		primary: 'bg-cta text-on-cta hover:bg-cta-hover',
		secondary: 'border-[1.5px] border-[color-mix(in_srgb,var(--fg)_30%,transparent)] bg-transparent text-fg hover:border-fg hover:bg-hover/60',
		ghost: 'text-muted hover:bg-hover hover:text-fg',
		danger: 'bg-danger text-on-danger hover:opacity-90',
		'danger-ghost': 'text-danger hover:bg-danger-soft'
	};
	export const buttonSizes: Record<ButtonSize, string> = {
		xs: 'h-6 px-2 text-xs [&_svg]:size-3.5',
		sm: 'h-7 px-2.5 text-xs [&_svg]:size-3.5',
		md: 'h-9 px-4 text-sm [&_svg]:size-4'
	};
</script>

<script lang="ts">
	import type { Component, Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import { LoaderCircle } from '@lucide/svelte';
	import { cx } from '#lib/format.js';

	type Props = HTMLButtonAttributes & {
		variant?: ButtonVariant;
		size?: ButtonSize;
		/** Renders a link styled as a button. */
		href?: string;
		/** With `href`: download the target instead of opening it. */
		download?: string | boolean;
		loading?: boolean;
		icon?: Component<{ class?: string }>;
		iconRight?: Component<{ class?: string }>;
		children?: Snippet;
		ref?: HTMLElement | null;
	};
	let {
		variant = 'secondary',
		size = 'md',
		href,
		loading = false,
		icon: Icon,
		iconRight: IconRight,
		type = 'button',
		disabled,
		class: klass,
		children,
		ref = $bindable(null),
		...rest
	}: Props = $props();
	const cls = $derived(cx(buttonBase, buttonVariants[variant], buttonSizes[size], klass as string));
</script>

{#if href && !disabled}
	<a bind:this={ref} {href} class={cls} {...rest as Record<string, unknown>}>
		{#if Icon}<Icon />{/if}{@render children?.()}{#if IconRight}<IconRight />{/if}
	</a>
{:else}
	<button bind:this={ref} {type} class={cls} disabled={disabled || loading} aria-busy={loading || undefined} {...rest}>
		{#if loading}<LoaderCircle class="animate-spin" />{:else if Icon}<Icon />{/if}{@render children?.()}{#if IconRight}<IconRight />{/if}
	</button>
{/if}
