<script lang="ts">
	import { Dialog } from 'bits-ui';
	import { X } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { cx } from '#lib/format.js';
	import IconButton from './IconButton.svelte';

	/** A panel sliding in from the side (mobile navigation, peeks). Same focus handling as Modal. */
	let {
		open = $bindable(false),
		title,
		side = 'left',
		width = 'w-72',
		onclose,
		children
	}: { open?: boolean; title: string; side?: 'left' | 'right'; width?: string; onclose?: () => void; children: Snippet } = $props();
</script>

<Dialog.Root bind:open onOpenChange={(o) => !o && onclose?.()}>
	<Dialog.Portal>
		<Dialog.Overlay class="bg-overlay fixed inset-0 z-50" />
		<Dialog.Content
			class={cx(
				'border-border bg-raised shadow-pop fixed inset-y-0 z-50 flex max-w-[88vw] flex-col outline-none',
				side === 'left' ? 'left-0 border-r' : 'right-0 border-l',
				width
			)}
		>
			<div class="flex items-center justify-between px-3 py-2">
				<Dialog.Title class="text-muted text-xs font-medium">{title}</Dialog.Title>
				<Dialog.Close>
					{#snippet child({ props })}<IconButton {...props} icon={X} label="Close" size="sm" tooltip={false} />{/snippet}
				</Dialog.Close>
			</div>
			<div class="min-h-0 flex-1 overflow-y-auto">{@render children()}</div>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
