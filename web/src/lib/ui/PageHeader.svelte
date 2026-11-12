<script lang="ts">
	import type { Snippet } from 'svelte';
	import { num } from '#lib/format.js';
	import Breadcrumbs from './Breadcrumbs.svelte';
	import Menu, { type MenuItem } from './Menu.svelte';

	/** Title, item count, the primary action, and secondary actions in an overflow menu. */
	let {
		title,
		count,
		description,
		crumbs,
		menu,
		actions,
		meta,
		subtitle
	}: {
		title: string;
		count?: number | string | null;
		description?: string;
		crumbs?: { label: string; href?: string }[];
		menu?: MenuItem[];
		actions?: Snippet;
		/** Badges and status next to the title. */
		meta?: Snippet;
		/** One muted line of metadata under the title (status, OS, location). */
		subtitle?: Snippet;
	} = $props();
</script>

<header class="mb-6">
	{#if crumbs?.length}<Breadcrumbs items={crumbs} />{/if}
	<div class="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
		<div class="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
			<h1 class="truncate text-2xl leading-tight font-semibold tracking-tight">{title}</h1>
			{#if count != null}<span class="bg-sunken border-border text-muted rounded-md border px-2 py-0.5 text-sm font-medium tabular">{typeof count === 'number' ? num(count) : count}</span>{/if}
			{@render meta?.()}
		</div>
		{#if actions || menu?.length}
			<div class="flex items-center gap-2">
				{@render actions?.()}
				{#if menu?.length}<Menu items={menu} />{/if}
			</div>
		{/if}
	</div>
	{#if subtitle}<div class="text-muted mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">{@render subtitle()}</div>{/if}
	{#if description}<p class="text-muted mt-1.5 max-w-3xl text-sm leading-relaxed">{description}</p>{/if}
</header>
