<script lang="ts">
	import { cx } from '#lib/format.js';
	import type { TagColor } from '#lib/types.js';

	/** A tag, in one of the palette's colours. The name is always there, so colour is never the only signal. */
	let { name, color = 'slate', href, class: klass = '' }: { name: string; color?: TagColor; href?: string; class?: string } = $props();

	// Tints are mixed from the theme's own accents, so both themes keep their contrast.
	const tints: Record<TagColor, string> = {
		slate: 'bg-sunken text-muted border-border',
		red: 'bg-danger-soft text-danger border-transparent',
		orange: 'bg-warning-soft text-warning border-transparent',
		amber: 'bg-[color-mix(in_srgb,var(--warning-dot)_22%,var(--raised))] text-fg border-transparent',
		green: 'bg-success-soft text-success border-transparent',
		teal: 'bg-[color-mix(in_srgb,var(--success)_14%,var(--info-soft))] text-info border-transparent',
		blue: 'bg-info-soft text-info border-transparent',
		violet: 'bg-accent-soft text-accent-ink border-transparent',
		pink: 'bg-[color-mix(in_srgb,var(--danger)_10%,var(--accent-soft))] text-accent-ink border-transparent'
	};
	const cls = $derived(cx('inline-flex h-5 max-w-40 items-center rounded-full border px-2 align-middle text-xs leading-none font-medium whitespace-nowrap', tints[color] ?? tints.slate, klass));
</script>

{#if href}
	<a {href} class={cx(cls, 'hover:opacity-80')}><span class="truncate">{name}</span></a>
{:else}
	<span class={cls}><span class="truncate">{name}</span></span>
{/if}
