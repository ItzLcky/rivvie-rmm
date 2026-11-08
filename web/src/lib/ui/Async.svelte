<script lang="ts" generics="T">
	import type { Snippet } from 'svelte';
	import type { Resource } from '#lib/resource.svelte.js';
	import Skeleton from './Skeleton.svelte';
	import ErrorState from './ErrorState.svelte';

	/**
	 * The shared load states: a skeleton while there's nothing yet, an error with Retry, and
	 * `children(data)` once loaded. A failed background reload keeps the data and shows a
	 * small notice instead of blanking the page.
	 */
	let {
		res,
		children,
		skeleton,
		compact = false
	}: { res: Resource<T>; children: Snippet<[T]>; skeleton?: Snippet; compact?: boolean } = $props();
</script>

{#if res.data !== undefined && !res.loading}
	{#if res.error}
		<p class="border-warning/40 bg-warning-soft text-warning mb-3 rounded-md border px-3 py-1.5 text-xs" role="status">
			Showing older data: {res.error.message}. <button class="font-medium underline" onclick={() => res.reload()}>Retry</button>
		</p>
	{/if}
	{@render children(res.data)}
{:else if res.error}
	<ErrorState error={res.error} onretry={() => res.reload()} {compact} />
{:else if skeleton}
	{@render skeleton()}
{:else}
	<div class="space-y-3 py-2" aria-busy="true" aria-label="Loading">
		<Skeleton class="h-5 w-48" />
		<Skeleton class="h-4 w-full" lines={compact ? 2 : 4} />
	</div>
{/if}
