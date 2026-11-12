<script lang="ts">
	import Badge from '#lib/ui/Badge.svelte';
	import { statusLabel, statusTone } from './format';

	let { category }: { category: string } = $props();
</script>

<Badge tone={statusTone(category)} dot>{statusLabel(category)}</Badge>
