<script lang="ts">
	import { ChevronLeft, ChevronRight, ChevronsLeft } from '@lucide/svelte';
	import { num } from '#lib/format.js';
	import IconButton from './IconButton.svelte';

	/**
	 * Keyset paging: previous/next cursors rather than page numbers (the lists keep growing, and
	 * cursors stay stable while rows are added). Page size is a user preference.
	 */
	let {
		shown,
		total,
		exact = true,
		hasPrev,
		hasNext,
		pageSize,
		onprev,
		onnext,
		onfirst,
		onpagesize
	}: {
		shown: number;
		total: number;
		exact?: boolean;
		hasPrev: boolean;
		hasNext: boolean;
		pageSize: number;
		onprev: () => void;
		onnext: () => void;
		onfirst: () => void;
		onpagesize: (n: number) => void;
	} = $props();
</script>

<div class="text-muted flex flex-wrap items-center justify-between gap-3 px-3 py-2 text-xs">
	<span class="tabular">{num(shown)} shown of {num(total)}{exact ? '' : '+'}</span>
	<div class="flex items-center gap-3">
		<label class="flex items-center gap-1.5">
			Rows
			<select class="control h-7 w-auto py-0 pr-7 text-xs" value={pageSize} onchange={(e) => onpagesize(Number(e.currentTarget.value))}>
				{#each [25, 50, 100, 200] as n (n)}<option value={n}>{n}</option>{/each}
			</select>
		</label>
		<div class="flex items-center gap-0.5">
			<IconButton icon={ChevronsLeft} label="First page" size="sm" disabled={!hasPrev} onclick={onfirst} />
			<IconButton icon={ChevronLeft} label="Previous page" size="sm" disabled={!hasPrev} onclick={onprev} />
			<IconButton icon={ChevronRight} label="Next page" size="sm" disabled={!hasNext} onclick={onnext} />
		</div>
	</div>
</div>
