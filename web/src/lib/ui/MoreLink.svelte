<script lang="ts">
	import { ArrowRight } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	/**
	 * A quiet "go further" link for card headers and toolbars: muted text with an arrow,
	 * underlined only on hover. Use `.link` (underlined) for links inside running text.
	 */
	let { href, onclick, children }: { href?: string; onclick?: () => void; children: Snippet } = $props();
	const cls = 'text-muted hover:text-fg group inline-flex items-center gap-1 text-xs font-medium whitespace-nowrap hover:underline underline-offset-2';
</script>

{#if href}
	<a {href} class={cls}>{@render children()}<ArrowRight class="size-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" /></a>
{:else}
	<button type="button" {onclick} class={cls}>{@render children()}<ArrowRight class="size-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" /></button>
{/if}
