<script lang="ts">
	import { Switch } from 'bits-ui';
	import type { Snippet } from 'svelte';

	let {
		checked = $bindable(false),
		disabled = false,
		label,
		id,
		onchange,
		children
	}: { checked?: boolean; disabled?: boolean; label?: string; id?: string; onchange?: (c: boolean) => void; children?: Snippet } = $props();
</script>

{#snippet sw()}
	<Switch.Root
		{id}
		bind:checked
		{disabled}
		aria-label={children ? undefined : label}
		onCheckedChange={(c) => onchange?.(c)}
		class="bg-border-strong data-[state=checked]:bg-accent inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full p-0.5 transition-colors disabled:cursor-not-allowed disabled:opacity-50"
	>
		<Switch.Thumb class="bg-raised pointer-events-none block size-4 rounded-full shadow-card transition-transform data-[state=checked]:translate-x-4" />
	</Switch.Root>
{/snippet}

{#if children}
	<label class="inline-flex cursor-pointer items-start gap-2.5 text-sm">{@render sw()}<span>{@render children()}</span></label>
{:else}
	{@render sw()}
{/if}
