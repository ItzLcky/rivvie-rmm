<script lang="ts">
	import { FolderTree } from '@lucide/svelte';
	import { cx, num, plural } from '#lib/format.js';
	import { moduleLabels, setHref } from '#lib/policy/policy.js';
	import type { Category, SetRow } from '#lib/policy/types.js';
	import Badge from '#lib/ui/Badge.svelte';

	/**
	 * Policy sets as a tree: each with its devices and what it defines or overrides, so the
	 * tree reads as an overview of where every policy is set. `rows` in tree order.
	 */
	let {
		rows,
		categories = [],
		base = 0,
		label = 'Policy sets'
	}: {
		rows: SetRow[];
		categories?: Category[];
		/** Depth shown flush left (a subtree). */
		base?: number;
		label?: string;
	} = $props();

	const catName = (id: string) => categories.find((c) => c.id === id)?.name;
	function what(s: SetRow): string {
		const bits: string[] = [];
		if (s.items) bits.push(`Defines ${s.defines.map((m) => moduleLabels[m].toLowerCase()).join(', ')} (${plural(s.items, 'policy', 'policies')})`);
		if (s.overrides) bits.push(`Overrides ${s.overrides_modules.map((m) => moduleLabels[m].toLowerCase()).join(', ')}`);
		return bits.join(' · ');
	}
</script>

<ul class="divide-border divide-y" aria-label={label}>
	{#each rows as s (s.id)}
		{@const d = Math.max(0, s.depth - base)}
		{@const defaults = s.default_for.map(catName).filter(Boolean)}
		<li class="hover:bg-hover/50 flex items-start gap-3 px-4 py-2.5" style="padding-left: calc(1rem + {Math.min(d, 6)} * var(--tree-step))">
			<FolderTree class={cx('mt-0.5 size-4 shrink-0', s.builtin ? 'text-subtle' : 'text-accent')} aria-hidden="true" />
			<div class="min-w-0 flex-1">
				<div class="flex flex-wrap items-center gap-x-2 gap-y-1">
					<a class="hover:text-accent truncate font-medium" href={setHref(s.id)}><span class="sr-only">{d ? `Level ${d}: ` : ''}</span>{s.name}</a>
					{#if s.client_id}<Badge>{s.client_name ?? 'Client'} only</Badge>{/if}
					{#if defaults.length}<Badge tone="accent" title="The set devices in these categories use unless they're assigned another">Default for {defaults.join(', ')}</Badge>{/if}
				</div>
				{#if what(s) || s.description}
					<p class="text-muted mt-0.5 truncate text-xs">{[what(s), s.description].filter(Boolean).join(' · ')}</p>
				{/if}
			</div>
			<a class="text-muted hover:text-fg shrink-0 text-xs tabular whitespace-nowrap" href={setHref(s.id, 'devices')} aria-label="{plural(s.devices, 'device')} use {s.name}">{num(s.devices)} <span class="max-sm:hidden">{s.devices === 1 ? 'device' : 'devices'}</span></a>
		</li>
	{:else}
		<li class="text-muted px-4 py-6 text-center text-sm">No sets.</li>
	{/each}
</ul>

<style>
	ul {
		--tree-step: 0.75rem;
	}
	@media (min-width: 640px) {
		ul {
			--tree-step: 1.5rem;
		}
	}
</style>
