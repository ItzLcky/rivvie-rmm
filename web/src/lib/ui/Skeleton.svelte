<script lang="ts">
	import { cx } from '#lib/format.js';
	let { class: klass = 'h-4 w-full', lines = 1 }: { class?: string; lines?: number } = $props();
</script>

{#each Array(lines) as _, i (i)}
	<div class={cx('bg-hover animate-pulse rounded', klass, lines > 1 && i === lines - 1 && 'w-2/3')} aria-hidden="true"></div>
{/each}
