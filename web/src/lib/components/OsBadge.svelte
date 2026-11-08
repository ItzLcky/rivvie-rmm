<script lang="ts">
	import { osLabels } from '#lib/format.js';
	import OsIcon from './OsIcon.svelte';

	/** `muted` for table cells: the icon says the family, the name is secondary detail. */
	let { os, name, muted = false }: { os: string; name?: string; muted?: boolean } = $props();
</script>

<span class="inline-flex min-w-0 items-center gap-1.5 {muted ? 'text-muted' : ''}">
	<OsIcon {os} class="size-3.5 shrink-0" />
	<span class="truncate">{name || osLabels[os] || os}</span>
</span>
