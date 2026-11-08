<script lang="ts" module>
	import type { Component } from 'svelte';
	export type MenuItem =
		| {
				label: string;
				icon?: Component<{ class?: string }>;
				onSelect?: () => void;
				href?: string;
				danger?: boolean;
				disabled?: boolean;
				hint?: string;
		  }
		| { separator: true }
		| { heading: string };
</script>

<script lang="ts">
	import { DropdownMenu } from 'bits-ui';
	import { goto } from '$app/navigation';
	import { Ellipsis } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { cx } from '#lib/format.js';
	import IconButton from './IconButton.svelte';

	/** A dropdown menu; the default trigger is an overflow (…) button. */
	let {
		items,
		label = 'More actions',
		align = 'end',
		trigger
	}: { items: MenuItem[]; label?: string; align?: 'start' | 'end'; trigger?: Snippet<[Record<string, unknown>]> } = $props();
	const visible = $derived(items.filter(Boolean));
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		{#snippet child({ props })}
			{#if trigger}
				{@render trigger(props)}
			{:else}
				<IconButton {...props} icon={Ellipsis} {label} tooltip={false} />
			{/if}
		{/snippet}
	</DropdownMenu.Trigger>
	<DropdownMenu.Portal>
		<DropdownMenu.Content
			{align}
			sideOffset={4}
			class="border-border bg-raised shadow-pop z-50 min-w-44 rounded-lg border p-1 text-sm outline-none"
		>
			{#each visible as item, i (i)}
				{#if 'separator' in item}
					<DropdownMenu.Separator class="bg-border -mx-1 my-1 h-px" />
				{:else if 'heading' in item}
					<div class="text-muted px-2 pt-1.5 pb-1 text-xs font-medium">{item.heading}</div>
				{:else}
					<DropdownMenu.Item
						disabled={item.disabled}
						onSelect={() => (item.href ? goto(item.href) : item.onSelect?.())}
						class={cx(
							'flex h-8 cursor-pointer items-center gap-2 rounded-md px-2 outline-none select-none data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50 [&_svg]:size-4',
							item.danger ? 'text-danger data-[highlighted]:bg-danger-soft' : 'data-[highlighted]:bg-hover'
						)}
					>
						{#if item.icon}<item.icon class={item.danger ? '' : 'text-muted'} />{/if}
						<span class="flex-1">{item.label}</span>
						{#if item.hint}<span class="text-muted text-xs">{item.hint}</span>{/if}
					</DropdownMenu.Item>
				{/if}
			{/each}
		</DropdownMenu.Content>
	</DropdownMenu.Portal>
</DropdownMenu.Root>
