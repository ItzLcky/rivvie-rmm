<script lang="ts">
	let { keys }: { keys: string[] } = $props();
</script>

<span class="inline-flex items-center gap-0.5">{#each keys as k (k)}<kbd class="kbd">{k}</kbd>{/each}</span>
