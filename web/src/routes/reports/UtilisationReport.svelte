<script lang="ts">
	import { api, qs } from '#lib/api.js';
	import { resource } from '#lib/resource.svelte.js';
	import { fmtMinutes } from '#lib/work/time.js';
	import type { UtilisationReport } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';

	let { from, to }: { from: string; to: string } = $props();
	const report = resource(() => api.get<UtilisationReport>(`/reports/utilisation${qs({ from, to })}`));
	const pct = (p: number | null) => (p == null ? '–' : `${p}%`);
	const tone = (p: number | null) => (p == null ? '' : p > 110 ? 'text-danger' : p >= 70 ? 'text-success' : 'text-warning');
	const total = (rows: UtilisationReport['technicians'], k: 'logged_minutes' | 'billable_minutes' | 'available_minutes') => rows.reduce((n, r) => n + r[k], 0);
	const ratio = (n: number, d: number) => (d > 0 ? Math.round((n * 1000) / d) / 10 : null);
</script>

<Async res={report}>
	{#snippet children(r)}
		<section class="card" aria-labelledby="util-h">
			<header class="panel-head">
				<div>
					<h2 id="util-h" class="panel-title">Utilisation</h2>
					<p class="text-muted text-xs">Logged and billable time against each technician's weekly capacity (weekdays only).</p>
				</div>
			</header>
			{#if !r.technicians.length}
				<EmptyState compact title="No technicians" />
			{:else}
				{@const L = total(r.technicians, 'logged_minutes')}
				{@const B = total(r.technicians, 'billable_minutes')}
				{@const A = total(r.technicians, 'available_minutes')}
				<div class="overflow-x-auto">
					<table class="table">
						<caption class="sr-only">Utilisation per technician</caption>
						<thead>
							<tr>
								<th>Technician</th><th class="text-right">Logged</th><th class="text-right">Billable</th><th class="hidden text-right sm:table-cell">Available</th>
								<th class="w-48">Utilisation</th><th class="text-right">Billable %</th>
							</tr>
						</thead>
						<tbody>
							{#each r.technicians as t (t.user_id)}
								<tr>
									<td class="font-medium">{t.name}</td>
									<td class="text-right whitespace-nowrap tabular">{fmtMinutes(t.logged_minutes)}</td>
									<td class="text-right whitespace-nowrap tabular">{fmtMinutes(t.billable_minutes)}</td>
									<td class="hidden text-right whitespace-nowrap tabular sm:table-cell">{fmtMinutes(t.available_minutes)}</td>
									<td>
										<div class="flex items-center gap-2">
											<div class="bg-sunken h-2 min-w-16 flex-1 overflow-hidden rounded-full" aria-hidden="true">
												<div class="bg-accent h-full" style="width: {Math.min(100, t.utilisation_pct ?? 0)}%"></div>
											</div>
											<span class="w-14 text-right tabular {tone(t.utilisation_pct)}">{pct(t.utilisation_pct)}</span>
										</div>
									</td>
									<td class="text-right tabular">{pct(t.billable_pct)}</td>
								</tr>
							{/each}
						</tbody>
						<tfoot>
							<tr class="font-semibold">
								<td class="px-[var(--cell-x)] py-[var(--row-y)]">Everyone</td>
								<td class="px-[var(--cell-x)] text-right tabular">{fmtMinutes(L)}</td>
								<td class="px-[var(--cell-x)] text-right tabular">{fmtMinutes(B)}</td>
								<td class="hidden px-[var(--cell-x)] text-right tabular sm:table-cell">{fmtMinutes(A)}</td>
								<td class="px-[var(--cell-x)] text-right tabular">{pct(ratio(L, A))}</td>
								<td class="px-[var(--cell-x)] text-right tabular">{pct(ratio(B, A))}</td>
							</tr>
						</tfoot>
					</table>
				</div>
			{/if}
		</section>
	{/snippet}
</Async>
