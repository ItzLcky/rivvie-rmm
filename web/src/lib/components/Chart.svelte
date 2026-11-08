<script lang="ts">
	// Minimal dependency-free line chart for metric history. One series colour (the same metric
	// family reads as one family), a 0-100 scale, time ticks, and a crosshair with a point marker.
	// Axis labels are HTML so they don't stretch with the SVG.
	let {
		points,
		max = 100,
		unit = '%',
		color = 'var(--chart-1)',
		height = 96,
		label
	}: { points: { t: number; v: number }[]; max?: number; unit?: string; color?: string; height?: number; label: string } = $props();

	const W = 600;
	let hover = $state<number | null>(null);

	const t0 = $derived(points[0]?.t ?? 0);
	const t1 = $derived(points.at(-1)?.t ?? 1);
	const x = (t: number) => (t1 === t0 ? W : ((t - t0) / (t1 - t0)) * W);
	const y = (v: number) => height - (Math.min(v, max) / max) * (height - 8) - 4;
	const path = $derived(points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(''));
	const area = $derived(points.length ? `${path}L${x(t1)},${height}L${x(t0)},${height}Z` : '');
	const latest = $derived(points.at(-1)?.v);
	const avg = $derived(points.length ? points.reduce((a, p) => a + p.v, 0) / points.length : 0);
	const peak = $derived(points.length ? Math.max(...points.map((p) => p.v)) : 0);

	function onmove(e: PointerEvent) {
		const r = (e.currentTarget as SVGElement).getBoundingClientRect();
		const tx = t0 + ((e.clientX - r.left) / r.width) * (t1 - t0);
		let best = 0;
		for (let i = 1; i < points.length; i++) if (Math.abs(points[i].t - tx) < Math.abs(points[best].t - tx)) best = i;
		hover = points.length ? best : null;
	}
	const span = $derived(t1 - t0);
	const ticks = $derived(points.length > 1 ? [0, 0.25, 0.5, 0.75, 1].map((f) => t0 + f * span) : []);
	const tickLabel = (t: number) =>
		span <= 36 * 3600_000
			? new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
			: new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
	const fmt = (t: number) => new Date(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
</script>

<div class="relative">
	<div class="mb-1 flex items-baseline justify-between gap-2 text-xs">
		<span class="text-muted font-medium">{label}</span>
		{#if points.length}
			<span class="text-muted tabular">now <strong class="text-fg">{latest?.toFixed(0)}{unit}</strong> · avg {avg.toFixed(0)}{unit} · peak {peak.toFixed(0)}{unit}</span>
		{/if}
	</div>
	{#if points.length < 2}
		<div class="border-border text-muted flex items-center justify-center rounded-md border border-dashed text-xs" style="height: {height}px">Not enough data yet</div>
	{:else}
		<div class="grid grid-cols-[2.25rem_1fr] gap-x-2">
			<div class="text-muted relative tabular text-right text-xs" style="height: {height}px" aria-hidden="true">
				{#each [max, max / 2, 0] as g (g)}<span class="absolute right-0 -translate-y-1/2" style="top: {y(g)}px">{g}{unit}</span>{/each}
			</div>
			<div class="relative">
		<svg
			viewBox="0 0 {W} {height}"
			preserveAspectRatio="none"
			class="w-full touch-none"
			style="height: {height}px"
			role="img"
			aria-label="{label}: now {latest?.toFixed(0)}{unit}, average {avg.toFixed(0)}{unit}, peak {peak.toFixed(0)}{unit}"
			onpointermove={onmove}
			onpointerleave={() => (hover = null)}
		>
			{#each [0.5, 1] as g (g)}
				<line x1="0" x2={W} y1={y(max * g)} y2={y(max * g)} stroke="var(--chart-grid)" stroke-dasharray="3 4" vector-effect="non-scaling-stroke" />
			{/each}
			<path d={area} fill={color} fill-opacity="0.12" />
			<path d={path} fill="none" stroke={color} stroke-width="1.5" vector-effect="non-scaling-stroke" />
			{#if hover !== null}
				<line x1={x(points[hover].t)} x2={x(points[hover].t)} y1="0" y2={height} stroke="var(--border-strong)" vector-effect="non-scaling-stroke" />
			{/if}
		</svg>
			{#if hover !== null}
				<span class="bg-raised pointer-events-none absolute size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2" style="left: {((points[hover].t - t0) / span) * 100}%; top: {y(points[hover].v)}px; border-color: {color}"></span>
			{/if}
			</div>
			<span></span>
			<div class="text-muted tabular flex justify-between pt-1 text-xs" aria-hidden="true">
				{#each ticks as t (t)}<span>{tickLabel(t)}</span>{/each}
			</div>
		</div>
		{#if hover !== null}
			<div class="border-border bg-raised shadow-pop pointer-events-none absolute top-6 right-1 rounded border px-2 py-1 text-xs tabular">
				{points[hover].v.toFixed(1)}{unit} · {fmt(points[hover].t)}
			</div>
		{/if}
	{/if}
</div>
