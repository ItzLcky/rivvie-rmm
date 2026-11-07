<script lang="ts">
	let { value, label = '' }: { value: number; label?: string } = $props();
	const color = $derived(value >= 90 ? 'bg-red-500' : value >= 75 ? 'bg-amber-500' : 'bg-sky-500');
</script>

<div class="flex items-center gap-2" title={label}>
	<div class="h-1.5 w-full min-w-12 overflow-hidden rounded bg-slate-800">
		<div class="h-full {color}" style="width: {Math.min(100, Math.max(0, value))}%"></div>
	</div>
	<span class="w-10 text-right text-xs text-slate-400 tabular-nums">{value.toFixed(0)}%</span>
</div>
