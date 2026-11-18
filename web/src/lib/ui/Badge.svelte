<script lang="ts" module>
	export type Tone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | 'info';
	export const toneClasses: Record<Tone, string> = {
		neutral: 'bg-sunken text-muted border-border',
		accent: 'bg-accent-soft text-accent-ink border-transparent',
		success: 'bg-success-soft text-success border-transparent',
		warning: 'bg-warning-soft text-warning border-transparent',
		danger: 'bg-danger-soft text-danger border-transparent',
		info: 'bg-info-soft text-info border-transparent'
	};
	export const dotClasses: Record<Tone, string> = {
		neutral: 'bg-subtle',
		accent: 'bg-accent',
		success: 'bg-success',
		warning: 'bg-warning-dot',
		danger: 'bg-danger',
		info: 'bg-info'
	};
</script>

<script lang="ts">
	import type { Component, Snippet } from 'svelte';
	import { cx } from '#lib/format.js';

	/**
	 * A small status label. Always carries text, so meaning never depends on colour alone.
	 * One step below body text (12 px against 14 px), centred on the line box so it sits on the
	 * same baseline as its neighbours; use it for exceptions, not for the normal state.
	 */
	let {
		tone = 'neutral',
		dot = false,
		icon: Icon,
		title,
		class: klass = '',
		children
	}: { tone?: Tone; dot?: boolean; icon?: Component<{ class?: string }>; title?: string; class?: string; children: Snippet } = $props();
</script>

<span class={cx('inline-flex h-5 items-center gap-1 rounded-full border px-2 align-middle text-xs leading-none font-medium whitespace-nowrap', toneClasses[tone], klass)} {title}>
	{#if dot}<span class={cx('size-1.5 rounded-full', dotClasses[tone])} aria-hidden="true"></span>{/if}
	{#if Icon}<Icon class="size-3" />{/if}
	{@render children()}
</span>
