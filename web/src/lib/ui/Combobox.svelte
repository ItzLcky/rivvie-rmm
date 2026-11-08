<script lang="ts" module>
	export interface ComboItem {
		value: string;
		label: string;
		/** Secondary text (client name, interpreter...), also searched. */
		hint?: string;
	}
</script>

<script lang="ts">
	import { Combobox } from 'bits-ui';
	import { Check, ChevronsUpDown, X } from '@lucide/svelte';
	import { cx } from '#lib/format.js';

	/** A searchable picker for clients, sites, scripts and agents. Filters as you type. */
	let {
		value = $bindable(''),
		items,
		placeholder = 'Select…',
		label,
		id,
		clearable = false,
		disabled = false,
		onchange,
		class: klass = ''
	}: {
		value?: string;
		items: ComboItem[];
		placeholder?: string;
		/** Accessible name when there's no <label for>. */
		label?: string;
		id?: string;
		clearable?: boolean;
		disabled?: boolean;
		onchange?: (v: string) => void;
		class?: string;
	} = $props();

	let search = $state('');
	let open = $state(false);
	const filtered = $derived.by(() => {
		const q = search.trim().toLowerCase();
		const list = q ? items.filter((i) => `${i.label} ${i.hint ?? ''}`.toLowerCase().includes(q)) : items;
		return list.slice(0, 200);
	});
	const selected = $derived(items.find((i) => i.value === value));
</script>

<Combobox.Root
	type="single"
	bind:value
	bind:open
	{items}
	{disabled}
	onValueChange={(v) => {
		search = '';
		onchange?.(v);
	}}
	onOpenChange={(o) => {
		if (!o) search = '';
	}}
>
	<div class={cx('relative', klass)}>
		<Combobox.Input
			{id}
			aria-label={label}
			{placeholder}
			defaultValue={selected?.label}
			oninput={(e) => (search = e.currentTarget.value)}
			class="control pr-14"
		/>
		<div class="absolute inset-y-0 right-1 flex items-center">
			{#if clearable && value}
				<button
					type="button"
					class="text-muted hover:text-fg flex size-6 items-center justify-center rounded"
					aria-label="Clear"
					onclick={() => {
						value = '';
						onchange?.('');
					}}><X class="size-3.5" /></button
				>
			{/if}
			<Combobox.Trigger class="text-muted hover:text-fg flex size-6 items-center justify-center rounded" aria-label="Show options"><ChevronsUpDown class="size-3.5" /></Combobox.Trigger>
		</div>
	</div>
	<Combobox.Portal>
		<Combobox.Content
			sideOffset={4}
			class="border-border bg-raised shadow-pop z-[55] max-h-72 w-[var(--bits-combobox-anchor-width)] min-w-48 overflow-hidden rounded-lg border p-1 outline-none"
		>
			<Combobox.Viewport class="max-h-64 overflow-y-auto">
				{#each filtered as item (item.value)}
					<Combobox.Item
						value={item.value}
						label={item.label}
						class="data-[highlighted]:bg-hover flex h-8 cursor-pointer items-center gap-2 rounded-md px-2 text-sm outline-none select-none"
					>
						{#snippet children({ selected })}
							<span class="min-w-0 flex-1 truncate">{item.label}</span>
							{#if item.hint}<span class="text-muted max-w-[45%] truncate text-xs">{item.hint}</span>{/if}
							<Check class={cx('text-accent size-4 shrink-0', !selected && 'invisible')} />
						{/snippet}
					</Combobox.Item>
				{:else}
					<p class="text-muted px-2 py-3 text-center text-sm">No matches</p>
				{/each}
			</Combobox.Viewport>
		</Combobox.Content>
	</Combobox.Portal>
</Combobox.Root>
