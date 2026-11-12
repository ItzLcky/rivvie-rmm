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
		nav = false,
		children
	}: { open?: boolean; title: string; side?: 'left' | 'right'; width?: string; onclose?: () => void; /** Navy, for the navigation rail. */ nav?: boolean; children: Snippet } = $props();
</script>

<Dialog.Root bind:open onOpenChange={(o) => !o && onclose?.()}>
	<Dialog.Portal>
		<Dialog.Overlay class="bg-overlay fixed inset-0 z-50" />
		<Dialog.Content
			class={cx(
				'shadow-pop fixed inset-y-0 z-50 flex max-w-[88vw] flex-col outline-none',
				nav ? 'bg-nav border-nav-border text-nav-fg' : 'border-border bg-raised',
				side === 'left' ? 'left-0 border-r' : 'right-0 border-l',
				width
			)}
		>
			<div class={cx('flex items-center justify-between px-3 py-2', nav && 'absolute top-3.5 right-2 z-[1] p-0')}>
				<Dialog.Title class={cx('text-muted text-xs font-medium', nav && 'sr-only')}>{title}</Dialog.Title>
				<Dialog.Close>
					{#snippet child({ props })}<IconButton {...props} icon={X} label="Close" size="sm" tooltip={false} class={nav ? 'text-nav-muted hover:bg-nav-hover hover:text-white' : ''} />{/snippet}
				</Dialog.Close>
			</div>
			<div class={cx('min-h-0 flex-1 overflow-y-auto', nav && '[&>div]:w-full')}>{@render children()}</div>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
