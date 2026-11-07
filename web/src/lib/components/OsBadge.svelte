<script lang="ts">
	let { os }: { os: string } = $props();
	const map: Record<string, [string, string]> = {
		linux: ['Linux', 'text-amber-300 border-amber-900'],
		windows: ['Windows', 'text-sky-300 border-sky-900'],
		macos: ['macOS', 'text-slate-200 border-slate-700']
	};
	const [label, cls] = $derived(map[os] ?? [os, 'text-slate-400 border-slate-700']);
</script>

<span class="rounded border px-1.5 py-0.5 text-[11px] font-medium {cls}">{label}</span>
