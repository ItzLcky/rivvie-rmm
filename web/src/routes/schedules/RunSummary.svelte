<script lang="ts">
	import type { JobStatus } from '#lib/types.js';
	import Badge, { type Tone } from '#lib/ui/Badge.svelte';

	/** Job counts of one schedule run, e.g. "12 ok · 1 failed". */
	let { counts }: { counts: Partial<Record<JobStatus, number>> } = $props();
	const groups: [string, Tone, JobStatus[]][] = [
		['ok', 'success', ['succeeded']],
		['failed', 'danger', ['failed', 'error', 'timed_out', 'lost']],
		['running', 'info', ['sent']],
		['queued', 'neutral', ['queued', 'expired', 'cancelled']]
	];
	const shown = $derived(groups.map(([label, tone, ss]) => ({ label, tone, n: ss.reduce((t, s) => t + (counts[s] ?? 0), 0) })).filter((g) => g.n));
</script>

{#if shown.length}
	<span class="ml-1 inline-flex flex-wrap gap-1 align-middle">{#each shown as g (g.label)}<Badge tone={g.tone}>{g.n} {g.label}</Badge>{/each}</span>
{/if}
