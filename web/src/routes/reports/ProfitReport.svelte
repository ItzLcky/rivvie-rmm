<script lang="ts">
	import { api, qs } from '#lib/api.js';
	import { resource } from '#lib/resource.svelte.js';
	import { money } from '#lib/work/money.svelte.js';
	import { fmtMinutes } from '#lib/work/time.js';
	import type { ProfitabilityReport, ProfitRow } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';

	let { from, to }: { from: string; to: string } = $props();
	const report = resource(() => api.get<ProfitabilityReport>(`/reports/profitability${qs({ from, to })}`));

	function byCurrency(rows: ProfitRow[]): [string, ProfitRow[]][] {
		const m = new Map<string, ProfitRow[]>();
		for (const r of rows) m.set(r.currency, [...(m.get(r.currency) ?? []), r]);
		return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
	}
	const sum = (rows: ProfitRow[], k: 'revenue' | 'time_cost' | 'product_cost' | 'margin' | 'minutes') => rows.reduce((n, r) => n + r[k], 0);
	const pct = (n: number, d: number) => (d ? `${Math.round((n * 1000) / d) / 10}%` : '–');
</script>

<Async res={report}>
	{#snippet children(r)}
		{#if !r.clients.length}
			<div class="card"><EmptyState compact title="Nothing in this period" description="No invoices, time or products sold between these dates." /></div>
		{:else}
			<div class="space-y-5">
				{#each byCurrency(r.clients) as [cur, rows] (cur)}
					{@const rev = sum(rows, 'revenue')}
					{@const margin = sum(rows, 'margin')}
					<section class="card" aria-labelledby="profit-{cur}">
						<header class="panel-head">
							<h2 id="profit-{cur}" class="panel-title">Profitability <span class="text-muted text-sm font-normal">· {cur}</span></h2>
							<span class="text-sm">Margin <span class="font-semibold tabular {margin < 0 ? 'text-danger' : ''}">{money(margin, cur)}</span> <span class="text-muted">({pct(margin, rev)})</span></span>
						</header>
						<div class="overflow-x-auto">
							<table class="table">
								<caption class="sr-only">Revenue and cost per client in {cur}</caption>
								<thead>
									<tr>
										<th>Client</th><th class="text-right">Invoiced</th><th class="hidden text-right md:table-cell">Hours</th><th class="text-right">Time cost</th>
										<th class="hidden text-right sm:table-cell">Product cost</th><th class="text-right">Margin</th><th class="text-right">%</th>
									</tr>
								</thead>
								<tbody>
									{#each rows as c (c.client_id)}
										<tr>
											<td><a class="hover:underline" href="/clients/{c.client_id}">{c.name}</a></td>
											<td class="text-right whitespace-nowrap tabular">{money(c.revenue, cur)}</td>
											<td class="hidden text-right whitespace-nowrap tabular md:table-cell">{fmtMinutes(c.minutes)}</td>
											<td class="text-right whitespace-nowrap tabular">{money(c.time_cost, cur)}</td>
											<td class="hidden text-right whitespace-nowrap tabular sm:table-cell">{money(c.product_cost, cur)}</td>
											<td class="text-right whitespace-nowrap tabular {c.margin < 0 ? 'text-danger font-medium' : ''}">{money(c.margin, cur)}</td>
											<td class="text-right tabular {c.margin_pct != null && c.margin_pct < 0 ? 'text-danger' : ''}">{c.margin_pct == null ? '–' : `${c.margin_pct}%`}</td>
										</tr>
									{/each}
								</tbody>
								<tfoot>
									<tr class="font-semibold">
										<td class="px-[var(--cell-x)] py-[var(--row-y)]">Total</td>
										<td class="px-[var(--cell-x)] text-right tabular">{money(rev, cur)}</td>
										<td class="hidden px-[var(--cell-x)] text-right tabular md:table-cell">{fmtMinutes(sum(rows, 'minutes'))}</td>
										<td class="px-[var(--cell-x)] text-right tabular">{money(sum(rows, 'time_cost'), cur)}</td>
										<td class="hidden px-[var(--cell-x)] text-right tabular sm:table-cell">{money(sum(rows, 'product_cost'), cur)}</td>
										<td class="px-[var(--cell-x)] text-right tabular {margin < 0 ? 'text-danger' : ''}">{money(margin, cur)}</td>
										<td class="px-[var(--cell-x)] text-right tabular">{pct(margin, rev)}</td>
									</tr>
								</tfoot>
							</table>
						</div>
					</section>
				{/each}
				<p class="text-muted text-xs">Revenue is finalised, sent and paid invoices issued in the period. Time cost uses each technician's cost rate; product cost uses the cost when it was sold.</p>
			</div>
		{/if}
	{/snippet}
</Async>
