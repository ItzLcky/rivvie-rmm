<script lang="ts">
	import { Search, X } from '@lucide/svelte';
	import { searchTickets } from '#lib/work/meta.js';
	import type { TicketRef } from '#lib/work/types.js';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';

	/** Finds a ticket by number or words. `value` is the chosen ticket (or null). */
	let { value = $bindable(null), id, disabled = false }: { value?: TicketRef | null; id?: string; disabled?: boolean } = $props();

	let q = $state('');
	let results = $state<TicketRef[]>([]);
	let searching = $state(false);
	let active = $state(-1);
	const listId = $derived(`${id ?? 'ticket'}-results`);

	$effect(() => {
		const term = q.trim();
		if (!term) {
			results = [];
			return;
		}
		let stale = false;
		const t = setTimeout(async () => {
			searching = true;
			try {
				const r = await searchTickets(term);
				if (!stale) {
					results = r;
					active = r.length ? 0 : -1;
				}
			} catch {
				if (!stale) results = [];
			} finally {
				if (!stale) searching = false;
			}
		}, 200);
		return () => {
			stale = true;
			clearTimeout(t);
		};
	});

	function pick(t: TicketRef) {
		value = t;
		q = '';
		results = [];
	}
	function onkeydown(e: KeyboardEvent) {
		if (!results.length) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			active = (active + 1) % results.length;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			active = (active - 1 + results.length) % results.length;
		} else if (e.key === 'Enter' && active >= 0) {
			e.preventDefault();
			pick(results[active]);
		} else if (e.key === 'Escape') {
			e.stopPropagation();
			results = [];
		}
	}
</script>

{#if value}
	<div class="border-border-strong bg-sunken flex h-8 items-center gap-2 rounded-md border pr-1 pl-2.5 text-sm">
		<span class="text-muted font-mono text-xs">T-{value.number}</span>
		<span class="min-w-0 flex-1 truncate">{value.subject}</span>
		{#if value.client_name}<span class="text-muted hidden truncate text-xs sm:inline">{value.client_name}</span>{/if}
		{#if !disabled}<IconButton icon={X} size="sm" label="Clear ticket" onclick={() => (value = null)} />{/if}
	</div>
{:else}
	<div class="relative">
		<Input
			{id}
			icon={Search}
			bind:value={q}
			{disabled}
			placeholder="Ticket number or subject…"
			autocomplete="off"
			role="combobox"
			aria-expanded={results.length > 0}
			aria-controls={listId}
			aria-autocomplete="list"
			aria-activedescendant={active >= 0 && results.length ? `${listId}-${active}` : undefined}
			{onkeydown}
		/>
		{#if results.length}
			<ul id={listId} role="listbox" class="border-border bg-raised shadow-pop absolute inset-x-0 top-9 z-10 max-h-64 overflow-y-auto rounded-lg border py-1">
				{#each results as t, i (t.id)}
					<li
						id="{listId}-{i}"
						role="option"
						aria-selected={i === active}
						class="flex cursor-pointer items-center gap-2 px-2.5 py-1.5 text-sm {i === active ? 'bg-hover' : ''}"
						onmousedown={(e) => {
							e.preventDefault();
							pick(t);
						}}
						onmouseenter={() => (active = i)}
					>
						<span class="text-muted font-mono text-xs">T-{t.number}</span>
						<span class="min-w-0 flex-1 truncate">{t.subject}</span>
						{#if t.client_name}<span class="text-muted truncate text-xs">{t.client_name}</span>{/if}
					</li>
				{/each}
			</ul>
		{:else if q.trim() && !searching}
			<p class="hint" role="status">No tickets match.</p>
		{/if}
	</div>
{/if}
