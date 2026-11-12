<script lang="ts">
	import { cx } from '#lib/format.js';

	/** A report figure that isn't a plain count: a label, the value as text and a note. */
	let { label, value, note, tone }: { label: string; value: string; note?: string; tone?: 'success' | 'warning' | 'danger' } = $props();
	const color = $derived(tone === 'danger' ? 'text-danger' : tone === 'warning' ? 'text-warning' : tone === 'success' ? 'text-success' : 'text-fg');
</script>

<div class="card min-w-0 p-4">
	<div class="text-muted truncate text-[0.8125rem] font-medium">{label}</div>
	<div class={cx('mt-2 text-[1.75rem] leading-none font-semibold tracking-tight tabular', color)}>{value}</div>
	{#if note}<div class="text-muted mt-1.5 text-xs">{note}</div>{/if}
</div>
