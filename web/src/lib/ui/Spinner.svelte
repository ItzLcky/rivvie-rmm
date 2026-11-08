<script lang="ts">
	import { LoaderCircle } from '@lucide/svelte';
	let { class: klass = 'size-4', label = 'Loading' }: { class?: string; label?: string } = $props();
</script>

<LoaderCircle class="text-muted animate-spin {klass}" aria-label={label} role="status" />
