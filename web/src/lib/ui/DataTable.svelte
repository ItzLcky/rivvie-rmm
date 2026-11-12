<script lang="ts" module>
	import type { Snippet } from 'svelte';

	export interface Column<T> {
		id: string;
		label: string;
		/** Sort key passed to the server (or used locally); omit for unsortable columns. */
		sort?: string;
		cell: Snippet<[T]>;
		/** Can the user hide it from the column menu? Default true. */
		hideable?: boolean;
		/** Hidden until the user turns it on. */
		defaultHidden?: boolean;
		align?: 'right';
		/** Header cell class, e.g. a width. */
		class?: string;
		/** Hide below this breakpoint (phones get the essentials). */
		from?: 'sm' | 'md' | 'lg' | 'xl';
	}

	// Only the newest mounted table answers j/k, so a table inside a tab wins over the page's.
	const active: symbol[] = [];
</script>

<script lang="ts" generics="T">
	import { DropdownMenu } from 'bits-ui';
	import { goto } from '$app/navigation';
	import { ArrowDown, ArrowUp, ArrowUpDown, Check, Columns3, ListFilter, X } from '@lucide/svelte';
	import { cx, plural } from '#lib/format.js';
	import { prefs, setPref } from '#lib/prefs.svelte.js';
	import Button from './Button.svelte';
	import Checkbox from './Checkbox.svelte';
	import IconButton from './IconButton.svelte';
	import Skeleton from './Skeleton.svelte';
	import { scrollFade } from './scrollfade.js';

	let {
		id,
		caption,
		rows,
		columns,
		key,
		sort,
		selected = $bindable(),
		rowHref,
		rowClass,
		loading = false,
		busy = false,
		toolbar,
		filters,
		activeFilters = 0,
		bulk,
		empty,
		footer,
		scroll = true
	}: {
		/** Saves column choices under this name. */
		id: string;
		/** Accessible name of the table. */
		caption: string;
		rows: T[];
		columns: Column<T>[];
		key: (row: T) => string;
		sort?: { key: string; dir: 'asc' | 'desc'; toggle: (key: string) => void };
		/** Bind a Set to enable row selection and the bulk-action bar. */
		selected?: Set<string>;
		rowHref?: (row: T) => string;
		rowClass?: (row: T) => string;
		/** Nothing to show yet: skeleton rows. */
		loading?: boolean;
		/** Refreshing: dims the rows. */
		busy?: boolean;
		/** Always visible: the search box. */
		toolbar?: Snippet;
		/** Secondary filters: inline from `sm`, behind a "Filters" button on phones. */
		filters?: Snippet;
		/** How many of `filters` are set; shown on the phone button. */
		activeFilters?: number;
		bulk?: Snippet<[number]>;
		empty?: Snippet;
		footer?: Snippet;
		/** Scroll inside the card with a sticky header (long lists). */
		scroll?: boolean;
	} = $props();

	let filtersOpen = $state(false);
	const selectable = $derived(selected !== undefined);
	const hidden = $derived(new Set(prefs.columns?.[id] ?? columns.filter((c) => c.defaultHidden).map((c) => c.id)));
	const shown = $derived(columns.filter((c) => !hidden.has(c.id)));
	const from = { sm: 'hidden sm:table-cell', md: 'hidden md:table-cell', lg: 'hidden lg:table-cell', xl: 'hidden xl:table-cell' };

	function toggleColumn(colId: string, visible: boolean) {
		const next = new Set(hidden);
		if (visible) next.delete(colId);
		else next.add(colId);
		setPref('columns', { ...prefs.columns, [id]: [...next] });
	}

	const keys = $derived(rows.map(key));
	const allOn = $derived(selectable && rows.length > 0 && keys.every((k) => selected!.has(k)));
	const someOn = $derived(selectable && !allOn && keys.some((k) => selected!.has(k)));
	function toggleAll() {
		const s = new Set(selected);
		for (const k of keys) {
			if (allOn) s.delete(k);
			else s.add(k);
		}
		selected = s;
	}
	function toggleRow(k: string) {
		const s = new Set(selected);
		if (s.has(k)) s.delete(k);
		else s.add(k);
		selected = s;
	}

	// j/k row cursor, Enter to open, x to select.
	let cursor = $state(-1);
	let body = $state<HTMLTableSectionElement>();
	const me = Symbol('table');
	$effect(() => {
		active.push(me);
		return () => active.splice(active.indexOf(me), 1);
	});
	$effect(() => {
		void rows;
		cursor = -1;
	});
	function onkey(e: KeyboardEvent) {
		if (active.at(-1) !== me || e.ctrlKey || e.metaKey || e.altKey) return;
		const t = e.target as HTMLElement;
		if (t.closest('input, textarea, select, [contenteditable], [role=dialog], [role=menu], [role=listbox]')) return;
		if (document.querySelector('[role=dialog], [role=alertdialog]')) return;
		if (e.key === 'j' || e.key === 'k') {
			if (!rows.length) return;
			e.preventDefault();
			cursor = Math.max(0, Math.min(rows.length - 1, cursor + (e.key === 'j' ? 1 : -1)));
			body?.children[cursor]?.scrollIntoView({ block: 'nearest' });
		} else if ((e.key === 'Enter' || e.key === 'o') && cursor >= 0 && rowHref && rows[cursor]) {
			e.preventDefault();
			goto(rowHref(rows[cursor]));
		} else if (e.key === 'x' && cursor >= 0 && selectable && rows[cursor]) {
			e.preventDefault();
			toggleRow(key(rows[cursor]));
		}
	}

	/** Whole-row click opens the item, except on links, buttons and inputs inside it. */
	function rowClick(e: MouseEvent, row: T) {
		if (!rowHref || (e.target as HTMLElement).closest('a, button, input, label, [role=checkbox], [role=menuitem]')) return;
		if (window.getSelection()?.toString()) return; // selecting text, not clicking
		if (e.metaKey || e.ctrlKey) window.open(rowHref(row), '_blank');
		else goto(rowHref(row));
	}
</script>

<svelte:window onkeydown={onkey} />

<div class="card flex min-w-0 flex-col overflow-hidden">
	{#if toolbar || filters || columns.some((c) => c.hideable !== false)}
		<div class="border-border flex flex-wrap items-center gap-2 border-b px-4 py-3">
			<div class={cx('order-1 flex min-w-0 flex-1 flex-wrap items-center gap-2', filters && 'sm:flex-none')}>{@render toolbar?.()}</div>
			{#if filters}
				<Button class="order-2 sm:hidden" icon={ListFilter} aria-expanded={filtersOpen} aria-controls="{id}-filters" onclick={() => (filtersOpen = !filtersOpen)}>
					Filters{#if activeFilters}<span class="bg-accent text-on-accent tabular rounded-full px-1.5 text-xs leading-4">{activeFilters}</span>{/if}
				</Button>
				<div id="{id}-filters" class={cx('order-4 w-full flex-col gap-2 sm:order-2 sm:flex sm:w-auto sm:min-w-0 sm:flex-1 sm:flex-row sm:flex-wrap sm:items-center', filtersOpen ? 'flex' : 'hidden')}>{@render filters()}</div>
			{/if}
			<div class="order-3 ml-auto">
			<DropdownMenu.Root>
				<DropdownMenu.Trigger>
					{#snippet child({ props })}<IconButton {...props} icon={Columns3} label="Columns and density" size="sm" />{/snippet}
				</DropdownMenu.Trigger>
				<DropdownMenu.Portal>
					<DropdownMenu.Content align="end" sideOffset={4} class="border-border bg-raised shadow-pop z-50 min-w-48 rounded-lg border p-1 text-sm outline-none">
						<div class="text-muted px-2 pt-1.5 pb-1 text-xs font-medium">Columns</div>
						{#each columns.filter((c) => c.hideable !== false) as c (c.id)}
							<DropdownMenu.CheckboxItem
								checked={!hidden.has(c.id)}
								onCheckedChange={(v) => toggleColumn(c.id, v)}
								closeOnSelect={false}
								class="data-[highlighted]:bg-hover flex h-8 cursor-pointer items-center gap-2 rounded-md px-2 outline-none select-none"
							>
								{#snippet children({ checked })}
									<Check class={cx('size-4', !checked && 'invisible')} />{c.label}
								{/snippet}
							</DropdownMenu.CheckboxItem>
						{/each}
						<DropdownMenu.Separator class="bg-border -mx-1 my-1 h-px" />
						<div class="text-muted px-2 pt-1.5 pb-1 text-xs font-medium">Density</div>
						<DropdownMenu.RadioGroup value={prefs.density ?? 'compact'} onValueChange={(v) => setPref('density', v as 'compact' | 'comfortable')}>
							{#each [['compact', 'Compact'], ['comfortable', 'Comfortable']] as [v, l] (v)}
								<DropdownMenu.RadioItem value={v} closeOnSelect={false} class="data-[highlighted]:bg-hover flex h-8 cursor-pointer items-center gap-2 rounded-md px-2 outline-none select-none">
									{#snippet children({ checked })}<Check class={cx('size-4', !checked && 'invisible')} />{l}{/snippet}
								</DropdownMenu.RadioItem>
							{/each}
						</DropdownMenu.RadioGroup>
					</DropdownMenu.Content>
				</DropdownMenu.Portal>
			</DropdownMenu.Root>
			</div>
		</div>
	{/if}

	{#if selectable && selected!.size > 0 && bulk}
		<div class="border-border bg-accent-soft flex flex-wrap items-center gap-2 border-b px-4 py-2 text-sm" role="region" aria-label="Bulk actions">
			<span class="text-accent font-medium">{plural(selected!.size, 'selected', 'selected')}</span>
			<div class="flex flex-wrap items-center gap-2">{@render bulk(selected!.size)}</div>
			<button class="text-muted hover:text-fg ml-auto inline-flex items-center gap-1 text-xs" onclick={() => (selected = new Set())}><X class="size-3.5" />Clear</button>
		</div>
	{/if}

	<div use:scrollFade class={cx('scroll-fade min-h-0 overflow-auto', scroll && 'max-h-[max(24rem,calc(100dvh-16rem))]')}>
		<table class="w-full border-separate border-spacing-0 text-left text-sm" aria-label={caption} aria-busy={loading || busy || undefined}>
			<thead class="bg-sunken sticky top-0 z-[1]">
				<tr>
					{#if selectable}
						<th class="border-border w-9 border-b" style="padding: var(--row-y) 0 var(--row-y) var(--cell-x)">
							<Checkbox checked={allOn} indeterminate={someOn} label="Select all on this page" onchange={toggleAll} />
						</th>
					{/if}
					{#each shown as c (c.id)}
						{@const sorted = sort && c.sort && sort.key === c.sort}
						<th
							scope="col"
							class={cx('border-border text-muted border-b text-xs font-semibold whitespace-nowrap', c.align === 'right' && 'text-right', c.from && from[c.from], c.class)}
							style="padding: var(--row-y) var(--cell-x)"
							aria-sort={sorted ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : undefined}
						>
							{#if sort && c.sort}
								<button class={cx('hover:text-fg group -mx-1 inline-flex items-center gap-1 rounded px-1', sorted && 'text-fg')} onclick={() => sort!.toggle(c.sort!)}>
									{c.label}
									{#if sorted}
										{#if sort.dir === 'asc'}<ArrowUp class="size-3" />{:else}<ArrowDown class="size-3" />{/if}
									{:else}
										<ArrowUpDown class="size-3 opacity-0 group-hover:opacity-60" />
									{/if}
								</button>
							{:else}
								{c.label}
							{/if}
						</th>
					{/each}
				</tr>
			</thead>
			<tbody bind:this={body} class={cx('transition-opacity', busy && !loading && 'opacity-60')}>
				{#if loading}
					{#each Array(6) as _, i (i)}
						<tr>
							{#if selectable}<td class="border-border border-b" style="padding: var(--row-y) var(--cell-x)"></td>{/if}
							{#each shown as c (c.id)}
								<td class={cx('border-border border-b', c.from && from[c.from])} style="padding: calc(var(--row-y) + 0.2rem) var(--cell-x)"><Skeleton class="h-3.5 w-4/5" /></td>
							{/each}
						</tr>
					{/each}
				{:else}
					{#each rows as row, i (key(row))}
						{@const k = key(row)}
						<tr
							class={cx(
								'group/row hover:bg-hover/60',
								rowHref && 'cursor-pointer',
								selectable && selected!.has(k) && 'bg-accent-soft/50',
								cursor === i && 'bg-hover outline-accent outline-2 -outline-offset-2',
								rowClass?.(row)
							)}
							onclick={(e) => rowClick(e, row)}
						>
							{#if selectable}
								<td class="border-border border-b" style="padding: var(--row-y) 0 var(--row-y) var(--cell-x)">
									<Checkbox checked={selected!.has(k)} label="Select row" onchange={() => toggleRow(k)} />
								</td>
							{/if}
							{#each shown as c (c.id)}
								<td class={cx('border-border border-b align-middle', c.align === 'right' && 'text-right tabular', c.from && from[c.from])} style="padding: var(--row-y) var(--cell-x)">
									{@render c.cell(row)}
								</td>
							{/each}
						</tr>
					{:else}
						<tr>
							<td colspan={shown.length + (selectable ? 1 : 0)}>
								{#if empty}{@render empty()}{:else}<p class="text-muted py-10 text-center">Nothing here.</p>{/if}
							</td>
						</tr>
					{/each}
				{/if}
			</tbody>
		</table>
	</div>
	{#if footer}<div class="border-border border-t">{@render footer()}</div>{/if}
</div>
