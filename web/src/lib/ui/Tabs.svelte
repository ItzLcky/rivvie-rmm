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
	<Tabs.List aria-label={label} class="border-border flex w-max min-w-full gap-1 border-b">
		{#each items.filter((i) => !i.hidden) as t (t.value)}
			<Tabs.Trigger
				value={t.value}
				title={t.title}
				class="text-muted hover:text-fg data-[state=active]:text-fg data-[state=active]:after:bg-accent relative inline-flex h-9 shrink-0 cursor-pointer items-center gap-1.5 px-2.5 text-sm font-medium whitespace-nowrap after:absolute after:inset-x-1 after:-bottom-px after:h-0.5 after:rounded-full [&_svg]:size-4"
			>
				{#if t.icon}<t.icon />{/if}
				{t.label}
				{#if t.count !== undefined}<span class="text-muted text-xs font-normal tabular">{t.count}</span>{/if}
			</Tabs.Trigger>
		{/each}
	</Tabs.List>
	</div>
</Tabs.Root>
