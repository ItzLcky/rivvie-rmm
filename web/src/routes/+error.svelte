<script lang="ts">
	import { page } from '$app/state';
	import { CircleAlert, SearchX } from '@lucide/svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
</script>

<svelte:head><title>{page.status === 404 ? 'Not found' : 'Error'}</title></svelte:head>

<div class="flex min-h-[60vh] items-center justify-center p-4">
	<EmptyState
		icon={page.status === 404 ? SearchX : CircleAlert}
		title={page.status === 404 ? 'Page not found' : 'Something went wrong'}
		description={page.status === 404 ? 'The link may be out of date, or the item was deleted.' : (page.error?.message ?? 'An unexpected error occurred.')}
	>
		{#snippet action()}<Button variant="primary" href="/">Go to the dashboard</Button>{/snippet}
	</EmptyState>
</div>
