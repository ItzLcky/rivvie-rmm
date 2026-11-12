<script lang="ts">
	import type { Component, Snippet } from 'svelte';
	import { Inbox } from '@lucide/svelte';
	import { cx } from '#lib/format.js';

	let {
		title,
		description,
		icon: Icon = Inbox,
		compact = false,
		action
	}: { title: string; description?: string; icon?: Component<{ class?: string }>; compact?: boolean; action?: Snippet } = $props();
</script>

<div class={cx('flex flex-col items-center justify-center text-center', compact ? 'gap-1 py-6' : 'gap-2 py-12')}>
	<div class={cx('bg-accent-soft text-accent flex items-center justify-center rounded-lg', compact ? 'mb-1 size-9' : 'mb-2 size-12')}>
		<Icon class={compact ? 'size-4' : 'size-5'} />
	</div>
	<p class="text-[0.9375rem] font-semibold">{title}</p>
	{#if description}<p class="text-muted max-w-sm text-sm">{description}</p>{/if}
	{#if action}<div class="mt-3">{@render action()}</div>{/if}
</div>
