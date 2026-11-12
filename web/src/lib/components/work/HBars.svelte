<script lang="ts">
	import { cx } from '#lib/format.js';

	/** Horizontal bars as a list: each row has its label and value as text; the bar is decoration. */
	let {
		items,
		max,
		label,
		tone = 'accent'
	}: { items: { label: string; value: number; text?: string }[]; max?: number; label: string; tone?: 'accent' | 'warning' | 'danger' | 'success' } = $props();
	const top = $derived(max ?? Math.max(1, ...items.map((i) => i.value)));
	const fill = { accent: 'bg-accent', warning: 'bg-warning', danger: 'bg-danger', success: 'bg-success' };
</script>

<ul class="space-y-1.5" aria-label={label}>
	{#each items as i (i.label)}
		<li class="grid grid-cols-[minmax(5rem,9rem)_1fr_auto] items-center gap-2 text-sm">
			<span class="text-muted truncate" title={i.label}>{i.label}</span>
			<span class="bg-sunken h-2 overflow-hidden rounded-full" aria-hidden="true">
				<span class={cx('block h-full rounded-full', fill[tone])} style="width: {Math.min(100, (Math.max(0, i.value) / top) * 100)}%"></span>
			</span>
			<span class="w-16 text-right tabular">{i.text ?? i.value}</span>
		</li>
	{/each}
</ul>
