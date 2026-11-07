<script lang="ts">
	let { online }: { online: boolean } = $props();
</script>

<span class="inline-flex items-center gap-1.5 text-xs {online ? 'text-emerald-400' : 'text-slate-500'}">
	<span class="size-2 rounded-full {online ? 'bg-emerald-400 shadow-[0_0_6px] shadow-emerald-400/60' : 'bg-slate-600'}"></span>
	{online ? 'Online' : 'Offline'}
</span>
