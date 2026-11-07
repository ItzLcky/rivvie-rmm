<script lang="ts">
	// Minimal dependency-free line chart for metric history.
	let {
		points,
		max = 100,
		unit = '%',
		color = '#38bdf8',
		height = 120
	}: { points: { t: number; v: number }[]; max?: number; unit?: string; color?: string; height?: number } = $props();

	const W = 600;
	let hover = $state<number | null>(null);

	const t0 = $derived(points[0]?.t ?? 0);
	const t1 = $derived(points.at(-1)?.t ?? 1);
	const x = (t: number) => (t1 === t0 ? W : ((t - t0) / (t1 - t0)) * W);
	const y = (v: number) => height - (Math.min(v, max) / max) * (height - 8) - 4;
	const path = $derived(points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(''));
	const area = $derived(points.length ? `${path}L${x(t1)},${height}L${x(t0)},${height}Z` : '');

	function onmove(e: MouseEvent) {
		const r = (e.currentTarget as SVGElement).getBoundingClientRect();
		const tx = t0 + ((e.clientX - r.left) / r.width) * (t1 - t0);
		let best = 0;
		for (let i = 1; i < points.length; i++) if (Math.abs(points[i].t - tx) < Math.abs(points[best].t - tx)) best = i;
		hover = points.length ? best : null;
	}
</script>

<div class="relative">
	{#if points.length < 2}
		<div class="flex items-center justify-center text-xs text-slate-500" style="height: {height}px">Not enough data yet</div>
	{:else}
		<svg viewBox="0 0 {W} {height}" preserveAspectRatio="none" class="w-full" style="height: {height}px" role="img" onmousemove={onmove} onmouseleave={() => (hover = null)}>
			{#each [0.25, 0.5, 0.75] as g (g)}
				<line x1="0" x2={W} y1={y(max * g)} y2={y(max * g)} stroke="#1e293b" stroke-dasharray="3 4" vector-effect="non-scaling-stroke" />
			{/each}
			<path d={area} fill={color} fill-opacity="0.12" />
			<path d={path} fill="none" stroke={color} stroke-width="1.5" vector-effect="non-scaling-stroke" />
			{#if hover !== null}
				<line x1={x(points[hover].t)} x2={x(points[hover].t)} y1="0" y2={height} stroke="#64748b" vector-effect="non-scaling-stroke" />
			{/if}
		</svg>
		{#if hover !== null}
			<div class="pointer-events-none absolute top-1 right-1 rounded bg-slate-800/90 px-2 py-1 text-xs text-slate-200 tabular-nums">
				{points[hover].v.toFixed(1)}{unit} · {new Date(points[hover].t).toLocaleTimeString()}
			</div>
		{/if}
	{/if}
</div>
