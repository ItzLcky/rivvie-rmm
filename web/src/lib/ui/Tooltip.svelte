<script lang="ts">
	import { Tooltip } from 'bits-ui';
	import type { Snippet } from 'svelte';

	/** Wraps a trigger (spread the `trigger` snippet's props onto it) with a hover/focus tooltip. */
	let {
		text,
		side = 'top',
		disabled = false,
		trigger
	}: { text: string; side?: 'top' | 'right' | 'bottom' | 'left'; disabled?: boolean; trigger: Snippet<[Record<string, unknown>]> } = $props();
</script>

{#if disabled}
	{@render trigger({})}
{:else}
	<Tooltip.Root delayDuration={300}>
		<Tooltip.Trigger>
			{#snippet child({ props })}{@render trigger(props)}{/snippet}
		</Tooltip.Trigger>
		<Tooltip.Portal>
			<Tooltip.Content
				{side}
				sideOffset={6}
				class="bg-fg text-surface z-[60] max-w-xs rounded-md px-2 py-1 text-xs font-medium shadow-pop data-[state=closed]:animate-out"
			>
				{text}
			</Tooltip.Content>
		</Tooltip.Portal>
	</Tooltip.Root>
{/if}
