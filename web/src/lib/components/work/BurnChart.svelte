<script lang="ts">
	import { dayLabel, fmtMinutes, hours } from '#lib/work/time.js';

	/**
	 * Hours logged per week, with the budget left after each week underneath (a burn-down when
	 * there's a budget). The same figures are in a table for screen readers.
	 */
	let { burn, budget }: { burn: { week: string; minutes: number }[]; budget: number } = $props();

	const rows = $derived.by(() => {
		let used = 0;
		return burn.map((b) => {
			used += b.minutes;
			return { ...b, used, left: budget - used };
		});
	});
	const max = $derived(Math.max(1, ...burn.map((b) => b.minutes)));
	const H = 120;
	const barW = 28;
	const gap = 10;
	const width = $derived(Math.max(1, rows.length) * (barW + gap) + gap);
</script>

{#if !rows.length}
	<p class="text-muted text-sm">No time logged yet.</p>
{:else}
	<div class="overflow-x-auto pb-1" aria-hidden="true">
		<svg viewBox="0 0 {width} {H + 34}" width={width} height={H + 34} class="block">
			<line x1="0" x2={width} y1={H} y2={H} stroke="var(--chart-grid)" />
			{#each rows as r, i (r.week)}
				{@const h = Math.max(2, (r.minutes / max) * (H - 16))}
				{@const x = gap + i * (barW + gap)}
				<rect {x} y={H - h} width={barW} height={h} rx="3" fill={budget > 0 && r.left < 0 ? 'var(--danger)' : 'var(--chart-1)'}>
					<title>{dayLabel(r.week, { day: 'numeric', month: 'short' })}: {fmtMinutes(r.minutes)}</title>
				</rect>
				<text x={x + barW / 2} y={H - h - 4} text-anchor="middle" font-size="10" fill="var(--muted)">{hours(r.minutes, 1)}</text>
				<text x={x + barW / 2} y={H + 13} text-anchor="middle" font-size="10" fill="var(--muted)">{dayLabel(r.week, { day: 'numeric', month: 'numeric' })}</text>
				{#if budget > 0}
					<text x={x + barW / 2} y={H + 27} text-anchor="middle" font-size="10" fill={r.left < 0 ? 'var(--danger)' : 'var(--fg)'}>{hours(r.left, 0)}</text>
				{/if}
			{/each}
		</svg>
	</div>
	<p class="text-muted mt-1 text-xs" aria-hidden="true">Bars: hours logged each week (week starting).{budget > 0 ? ' Below: budget hours left after that week.' : ''}</p>
	<table class="sr-only">
		<caption>Time logged per week</caption>
		<thead><tr><th>Week starting</th><th>Logged</th>{#if budget > 0}<th>Budget left</th>{/if}</tr></thead>
		<tbody>
			{#each rows as r (r.week)}
				<tr><td>{dayLabel(r.week, { day: 'numeric', month: 'long', year: 'numeric' })}</td><td>{fmtMinutes(r.minutes)}</td>{#if budget > 0}<td>{fmtMinutes(r.left)}</td>{/if}</tr>
			{/each}
		</tbody>
	</table>
{/if}
