<script lang="ts" module>
	import type { Component } from 'svelte';
	export interface TabItem {
		value: string;
		label: string;
		count?: number | string;
		icon?: Component<{ class?: string }>;
		hidden?: boolean;
		/** Tooltip, e.g. to spell out a short label. */
		title?: string;
	}
</script>

<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { cx } from '#lib/format.js';
	import { scrollFade } from './scrollfade.js';

	/**
	 * Tabs with full keyboard support (arrows, Home/End). The list only: render the panel for
	 * `value` yourself, so each tab can live in the URL (`?tab=`) and load lazily. Also used for
	 * list views (All / Online / Offline) with a count on each. When the strip is wider than its
	 * container (phones) it scrolls, and the edge that has more fades out.
	 */
	let {
		items,
		value,
		onchange,
		label,
		class: klass = ''
	}: { items: TabItem[]; value: string; onchange: (v: string) => void; label: string; class?: string } = $props();
</script>

<Tabs.Root {value} onValueChange={(v) => v && onchange(v)} activationMode="manual">
	<div use:scrollFade class={cx('scroll-fade scrollbar-thin -mx-1 overflow-x-auto px-1', klass)}>
	<Tabs.List aria-label={label} class="border-border flex w-max min-w-full gap-2 border-b">
		{#each items.filter((i) => !i.hidden) as t (t.value)}
			<Tabs.Trigger
				value={t.value}
				title={t.title}
				class="text-muted hover:text-fg data-[state=active]:text-accent data-[state=active]:after:bg-accent group relative inline-flex h-10 shrink-0 cursor-pointer items-center gap-2 px-2 text-sm font-medium whitespace-nowrap transition-colors after:absolute after:inset-x-0 after:-bottom-px after:h-0.5 after:rounded-t-full [&_svg]:size-4"
			>
				{#if t.icon}<t.icon />{/if}
				{t.label}
				{#if t.count !== undefined}<span class="bg-sunken text-muted group-data-[state=active]:bg-accent-soft group-data-[state=active]:text-accent min-w-5 rounded-full px-1.5 text-center text-xs leading-5 font-medium tabular">{t.count}</span>{/if}
			</Tabs.Trigger>
		{/each}
	</Tabs.List>
	</div>
</Tabs.Root>
