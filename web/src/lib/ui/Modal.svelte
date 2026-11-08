<script lang="ts">
	import { Dialog } from 'bits-ui';
	import { X } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { cx } from '#lib/format.js';
	import IconButton from './IconButton.svelte';

	/**
	 * A dialog. Focus is trapped inside while open and returns to where it was when it closes.
	 * Mount it with `{#if}` and close via `onclose`, or bind `open`.
	 */
	let {
		title,
		description,
		onclose,
		open = $bindable(true),
		size = 'md',
		children,
		footer
	}: {
		title: string;
		description?: string;
		onclose?: () => void;
		open?: boolean;
		size?: 'sm' | 'md' | 'lg' | 'xl';
		children: Snippet;
		/** Buttons, right-aligned in a footer bar. */
		footer?: Snippet;
	} = $props();

	const widths = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-3xl', xl: 'max-w-5xl' };

	// Bits returns focus to its Trigger; these dialogs usually have none (they're opened from
	// menus, palettes or code), so remember and restore the previously focused element.
	const previous = typeof document !== 'undefined' ? (document.activeElement as HTMLElement | null) : null;
	$effect(() => () => {
		if (previous?.isConnected) setTimeout(() => previous.focus(), 0);
	});
</script>

<Dialog.Root
	bind:open
	onOpenChange={(o) => {
		if (!o) onclose?.();
	}}
>
	<Dialog.Portal>
		<Dialog.Overlay class="bg-overlay fixed inset-0 z-50 backdrop-blur-[1px]" />
		<Dialog.Content
			class={cx(
				'border-border bg-raised shadow-pop fixed top-[max(1rem,8vh)] left-1/2 z-50 flex max-h-[calc(100dvh-2rem)] w-[calc(100vw-1.5rem)] -translate-x-1/2 flex-col rounded-xl border outline-none sm:max-h-[84vh]',
				widths[size]
			)}
		>
			<div class="border-border flex items-start justify-between gap-3 border-b px-4 py-3">
				<div class="min-w-0">
					<Dialog.Title class="truncate text-base font-semibold">{title}</Dialog.Title>
					{#if description}<Dialog.Description class="text-muted mt-0.5 text-sm">{description}</Dialog.Description>{/if}
				</div>
				<Dialog.Close>
					{#snippet child({ props })}<IconButton {...props} icon={X} label="Close" size="sm" tooltip={false} />{/snippet}
				</Dialog.Close>
			</div>
			<div class="min-h-0 flex-1 overflow-y-auto p-4">{@render children()}</div>
			{#if footer}
				<div class="border-border bg-sunken/50 flex flex-wrap justify-end gap-2 rounded-b-xl border-t px-4 py-3">{@render footer()}</div>
			{/if}
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
