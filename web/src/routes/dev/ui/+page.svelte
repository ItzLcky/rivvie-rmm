<script lang="ts">
	const enabled = import.meta.env.DEV || !!import.meta.env.VITE_UI_GALLERY;
</script>

<svelte:head><title>UI gallery</title></svelte:head>

{#if enabled}
	{#await import('./Gallery.svelte') then G}<G.default />{/await}
{/if}
