<script lang="ts">
	import { api, qs } from '#lib/api.js';
	import { num } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { fmtMinutes } from '#lib/work/time.js';
	import type { Breakdown, ServiceDeskReport } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import HBars from '#lib/components/work/HBars.svelte';
	import Kpi from './Kpi.svelte';

	let { from, to, clientId }: { from: string; to: string; clientId: string } = $props();
	const report = resource(() => api.get<ServiceDeskReport>(`/reports/service-desk${qs({ from, to, client_id: clientId })}`));

	const pctText = (p: number | null) => (p == null ? '–' : `${p}%`);
	const pctTone = (p: number | null) => (p == null ? undefined : p >= 95 ? 'success' : p >= 80 ? 'warning' : 'danger');
	const tables: { key: 'by_client' | 'by_board' | 'by_technician' | 'by_type'; label: string; col: string }[] = [
		{ key: 'by_client', label: 'By client', col: 'Client' },
		{ key: 'by_board', label: 'By board', col: 'Board' },
		{ key: 'by_technician', label: 'By technician', col: 'Technician' },
		{ key: 'by_type', label: 'By type', col: 'Type' }
	];
	const top = (rows: Breakdown[]) => Math.max(1, ...rows.map((r) => Math.max(r.opened, r.closed)));
</script>

<Async res={report}>
	{#snippet children(r)}
		<h2 class="sr-only">Service desk</h2>
		<div class="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
			<Stat label="Opened" value={r.opened} />
			<Stat label="Resolved" value={r.closed} />
			<Stat label="Open now" value={r.backlog} />
			<Kpi label="Median first response" value={r.first_response_median_mins == null ? '–' : fmtMinutes(r.first_response_median_mins)} />
			<Kpi label="Median resolution" value={r.resolution_median_mins == null ? '–' : fmtMinutes(r.resolution_median_mins)} />
			<Kpi
				label="Satisfaction"
				value={pctText(r.csat.pct)}
				tone={pctTone(r.csat.pct)}
				note={r.csat.good + r.csat.bad ? `${num(r.csat.good)} good · ${num(r.csat.bad)} bad` : 'No answers'}
			/>
		</div>

		<div class="mt-5 grid gap-5 lg:grid-cols-2">
			<section class="card p-4" aria-labelledby="sla-h">
				<h3 id="sla-h" class="panel-title mb-3">SLA attainment</h3>
				<div class="grid grid-cols-2 gap-3">
					{#each [{ k: 'respond', l: 'First response' }, { k: 'resolve', l: 'Resolution' }] as const as x (x.k)}
						{@const a = r.sla[x.k]}
						<div>
							<div class="text-muted text-xs font-medium">{x.l} within target</div>
							<div class="mt-1 text-2xl font-semibold tabular {a.pct == null ? '' : a.pct >= 95 ? 'text-success' : a.pct >= 80 ? 'text-warning' : 'text-danger'}">{pctText(a.pct)}</div>
							<div class="text-muted text-xs">{num(a.met)} of {num(a.total)} tickets</div>
							<div class="bg-sunken mt-2 h-2 overflow-hidden rounded-full" aria-hidden="true">
								<div class="bg-success h-full" style="width: {a.pct ?? 0}%"></div>
							</div>
						</div>
					{/each}
				</div>
			</section>
			<section class="card p-4" aria-labelledby="age-h">
				<h3 id="age-h" class="panel-title mb-3">Open tickets by age</h3>
				<HBars
					label="Open tickets by age"
					tone="warning"
					items={[
						{ label: 'Under a day', value: r.backlog_age.under_1d },
						{ label: '1–3 days', value: r.backlog_age['1_3d'] },
						{ label: '3–7 days', value: r.backlog_age['3_7d'] },
						{ label: '7–30 days', value: r.backlog_age['7_30d'] },
						{ label: 'Over 30 days', value: r.backlog_age.over_30d }
					]}
				/>
			</section>
		</div>

		<div class="mt-5 grid gap-5 lg:grid-cols-2">
			{#each tables as t (t.key)}
				{@const rows = r[t.key]}
				<section class="card" aria-labelledby="{t.key}-h">
					<header class="panel-head"><h3 id="{t.key}-h" class="panel-title">{t.label}</h3></header>
					{#if !rows.length}
						<p class="text-muted px-4 py-3 text-sm">No tickets in this period.</p>
					{:else}
						<div class="max-h-96 overflow-auto">
							<table class="table">
								<caption class="sr-only">Tickets {t.label.toLowerCase()}</caption>
								<thead><tr><th>{t.col}</th><th class="text-right">Opened</th><th class="text-right">Resolved</th><th class="hidden w-32 sm:table-cell"><span class="sr-only">Chart</span></th></tr></thead>
								<tbody>
									{#each rows as b (b.name)}
										<tr>
											<td class="max-w-56 truncate" title={b.name}>{b.name}</td>
											<td class="text-right tabular">{num(b.opened)}</td>
											<td class="text-right tabular">{num(b.closed)}</td>
											<td class="hidden sm:table-cell" aria-hidden="true">
												<div class="bg-accent h-1.5 rounded-full" style="width: {(b.opened / top(rows)) * 100}%"></div>
												<div class="bg-success mt-0.5 h-1.5 rounded-full" style="width: {(b.closed / top(rows)) * 100}%"></div>
											</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{/if}
				</section>
			{/each}
		</div>
	{/snippet}
</Async>
