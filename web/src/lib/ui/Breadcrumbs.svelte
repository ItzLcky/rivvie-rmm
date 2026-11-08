<script lang="ts">
	import { ChevronRight } from '@lucide/svelte';

	let { items }: { items: { label: string; href?: string }[] } = $props();
</script>

<nav aria-label="Breadcrumb" class="mb-1 min-w-0">
	<ol class="text-muted flex min-w-0 flex-wrap items-center gap-1 text-xs">
		{#each items as item, i (i)}
			<li class="flex min-w-0 items-center gap-1">
				{#if i > 0}<ChevronRight class="text-subtle size-3 shrink-0" aria-hidden="true" />{/if}
				{#if item.href && i < items.length - 1}
					<a href={item.href} class="hover:text-fg truncate">{item.label}</a>
				{:else}
					<span class="truncate" aria-current={i === items.length - 1 ? 'page' : undefined}>{item.label}</span>
				{/if}
			</li>
		{/each}
	</ol>
</nav>
