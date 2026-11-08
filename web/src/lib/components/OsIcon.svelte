<script lang="ts">
	import { Apple, Monitor, Server } from '@lucide/svelte';
	import { osLabels } from '#lib/format.js';

	/** A small OS glyph with its name as the accessible label (no brand logos). */
	let { os, class: klass = 'size-4' }: { os: string; class?: string } = $props();
	const Icon = $derived(os === 'macos' ? Apple : os === 'linux' ? Server : Monitor);
</script>

<Icon class="text-muted shrink-0 {klass}" aria-label={osLabels[os] ?? os} role="img" />
