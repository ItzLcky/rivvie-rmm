<script lang="ts" generics="V extends string">
	import { ToggleGroup } from 'bits-ui';

	/** A small single-choice switch (time ranges, views). */
	let {
		value,
		options,
		onchange,
		label,
		size = 'sm'
	}: { value: V; options: { value: V; label: string; count?: number }[]; onchange: (v: V) => void; label: string; size?: 'sm' | 'md' } = $props();
</script>

<ToggleGroup.Root
	type="single"
	{value}
	onValueChange={(v) => v && onchange(v as V)}
	aria-label={label}
	class="border-border bg-sunken inline-flex max-w-full overflow-x-auto rounded-md border p-0.5"
>
	{#each options as o (o.value)}
		<ToggleGroup.Item
			value={o.value}
			class="text-muted hover:text-fg data-[state=on]:bg-raised data-[state=on]:text-fg data-[state=on]:shadow-card inline-flex cursor-pointer items-center gap-1 rounded px-2.5 font-medium whitespace-nowrap {size === 'sm' ? 'h-6 text-xs' : 'h-7 text-sm'}"
		>
			{o.label}{#if o.count !== undefined}<span class="text-muted tabular">{o.count}</span>{/if}
		</ToggleGroup.Item>
	{/each}
</ToggleGroup.Root>
