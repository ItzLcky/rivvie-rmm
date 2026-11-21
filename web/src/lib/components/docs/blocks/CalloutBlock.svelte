<script lang="ts">
	import { Info, OctagonAlert, TriangleAlert } from '@lucide/svelte';
	import { calloutTone, renderMarkdown } from '#lib/docs/markdown.js';
	import type { BlockProps } from '#lib/docs/blocks.js';
	import BlockError from './BlockError.svelte';

	/** A tinted box: `callout info` (the default), `callout warning` or `callout danger`. */
	let { seg }: BlockProps = $props();
	const tone = $derived(calloutTone(seg.arg));
	const meta = { info: { icon: Info, label: 'Note' }, warning: { icon: TriangleAlert, label: 'Warning' }, danger: { icon: OctagonAlert, label: 'Danger' } };
</script>

{#if !tone}
	<BlockError {seg} message="the type must be info, warning or danger" />
{:else}
	{@const m = meta[tone]}
	<div class="doc-block doc-callout doc-callout-{tone}" role="note">
		<m.icon class="doc-callout-icon" aria-hidden="true" />
		<div class="doc-prose doc-callout-body">
			<span class="sr-only">{m.label}: </span>{@html renderMarkdown(seg.body)}
		</div>
	</div>
{/if}
