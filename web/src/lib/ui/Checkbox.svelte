<script lang="ts">
	import { Checkbox } from 'bits-ui';
	import { Check, Minus } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	let {
		checked = $bindable(false),
		indeterminate = false,
		disabled = false,
		label,
		id,
		onchange,
		children: text
	}: {
		checked?: boolean;
		indeterminate?: boolean;
		disabled?: boolean;
		/** Accessible name when there's no visible text (e.g. row selection). */
		label?: string;
		id?: string;
		onchange?: (checked: boolean) => void;
		children?: Snippet;
	} = $props();
</script>

{#snippet box()}
	<Checkbox.Root
		{id}
		bind:checked
		{indeterminate}
		{disabled}
		aria-label={text ? undefined : label}
		onCheckedChange={(c) => onchange?.(c)}
		class="border-border-strong bg-raised data-[state=checked]:border-accent data-[state=checked]:bg-accent data-[state=indeterminate]:border-accent data-[state=indeterminate]:bg-accent text-on-accent inline-flex size-4 shrink-0 cursor-pointer items-center justify-center rounded-[4px] border transition-colors disabled:cursor-not-allowed disabled:opacity-50"
	>
		{#snippet children({ checked, indeterminate })}
			{#if indeterminate}<Minus class="size-3" strokeWidth={3} />{:else if checked}<Check class="size-3" strokeWidth={3} />{/if}
		{/snippet}
	</Checkbox.Root>
{/snippet}

{#if text}
	<label class="inline-flex cursor-pointer items-center gap-2 text-sm">{@render box()}{@render text()}</label>
{:else}
	{@render box()}
{/if}
