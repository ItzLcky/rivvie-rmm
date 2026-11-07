<script lang="ts">
	import type { Snippet } from 'svelte';
	let { title, onclose, children, wide = false }: { title: string; onclose: () => void; children: Snippet; wide?: boolean } = $props();
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<div class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-[10vh]" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
	<div class="card w-full {wide ? 'max-w-3xl' : 'max-w-lg'} bg-slate-900 shadow-2xl" role="dialog" aria-modal="true" aria-label={title}>
		<div class="flex items-center justify-between border-b border-slate-800 px-4 py-3">
			<h2 class="font-semibold">{title}</h2>
			<button class="text-slate-400 hover:text-slate-100" onclick={onclose} aria-label="Close">✕</button>
		</div>
		<div class="p-4">{@render children()}</div>
	</div>
</div>
