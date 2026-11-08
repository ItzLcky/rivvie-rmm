<script lang="ts">
	import { RefreshCw, TriangleAlert } from '@lucide/svelte';
	import Button from './Button.svelte';

	let { error, onretry, compact = false }: { error: Error | string; onretry?: () => void; compact?: boolean } = $props();
	let busy = $state(false);
	async function retry() {
		busy = true;
		try {
			await onretry?.();
		} finally {
			busy = false;
		}
	}
</script>

<div class="flex flex-col items-center justify-center gap-2 text-center {compact ? 'py-6' : 'py-12'}" role="alert">
	<div class="bg-danger-soft text-danger mb-1 flex size-10 items-center justify-center rounded-full"><TriangleAlert class="size-5" /></div>
	<p class="font-medium">Couldn't load this</p>
	<p class="text-muted max-w-md text-sm">{typeof error === 'string' ? error : error.message}</p>
	{#if onretry}<Button class="mt-2" size="sm" icon={RefreshCw} loading={busy} onclick={retry}>Retry</Button>{/if}
</div>
