<script lang="ts">
	import { RotateCcw } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { runReason, triggerLabels } from '#lib/policy/policy.js';
	import type { ItemRuns, ItemView } from '#lib/policy/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { qs } from '#lib/url.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import RunStatus from './RunStatus.svelte';

	/** What an automation did, device by device; run-once automations can be reset here. */
	let { view, canReset = false }: { view: ItemView; canReset?: boolean } = $props();

	type Filter = 'all' | 'pending' | 'waiting' | 'succeeded' | 'failed' | 'skipped';
	let filter = $state<Filter>('all');
	const res = resource(() => api.get<ItemRuns>(`/policy-items/${view.id}/runs${qs({ status: filter === 'all' ? undefined : filter })}`));
	const runOnce = $derived(view.config.trigger === 'run_once');

	async function reset(agentIds: string[] | null, failedOnly: boolean, what: string) {
		const ok = await confirmAction({
			title: `Run ${view.name} again on ${what}?`,
			message: 'The record that it ran is deleted, so the next pass starts it again (within the hourly limit). Runs still in progress are left alone.',
			confirmLabel: 'Reset'
		});
		if (!ok) return;
		await attempt(async () => {
			await api.post(`/policy-items/${view.id}/runs/reset`, { agent_ids: agentIds ?? undefined, failed_only: failedOnly });
			await res.reload();
		}, `${view.name} will run again on ${what}.`);
	}
</script>

<section class="card" aria-labelledby="au-runs-h">
	<header class="panel-head">
		<div class="min-w-0">
			<h2 id="au-runs-h" class="panel-title">{runOnce ? 'Devices' : 'Runs'}</h2>
			<p class="text-muted text-xs">{runOnce ? 'Every device this automation reaches, with whether the script has run there.' : 'The latest runs on the devices you can see, newest first.'}</p>
		</div>
		{#if runOnce && canReset}
			<div class="flex flex-wrap gap-2">
				<Button size="sm" icon={RotateCcw} disabled={!res.data?.counts.failed} onclick={() => reset(null, true, 'devices where it failed')}>Retry failed</Button>
				<Button size="sm" variant="ghost" onclick={() => reset(null, false, 'every device')}>Reset all</Button>
			</div>
		{/if}
	</header>
	<Async {res}>
		{#snippet children(d)}
			<div class="border-border border-b px-4 py-2.5">
				<Segmented
					label="Filter runs by state"
					value={filter}
					onchange={(v) => (filter = v)}
					options={[
						{ value: 'all', label: 'All', count: Object.values(d.counts).reduce((a, b) => a + b, 0) },
						{ value: 'succeeded', label: 'Succeeded', count: d.counts.succeeded },
						{ value: 'failed', label: 'Failed', count: d.counts.failed },
						{ value: 'pending', label: 'Running', count: d.counts.pending },
						{ value: 'waiting', label: 'Waiting', count: d.counts.waiting },
						{ value: 'skipped', label: 'Skipped', count: d.counts.skipped }
					]}
				/>
			</div>
			{#snippet hostCell(r: ItemRuns['runs'][number])}<a class="hover:text-accent font-medium" href="/agents/{r.agent_id}?tab=policy">{r.hostname}</a>{/snippet}
			{#snippet statusCell(r: ItemRuns['runs'][number])}
				<RunStatus status={r.status} reason={r.reason} />
				{#if r.reason}<span class="text-muted mt-0.5 block text-xs">{runReason(r.reason)}</span>{/if}
			{/snippet}
			{#snippet whenCell(r: ItemRuns['runs'][number])}<span class="text-muted whitespace-nowrap" title={datetime(r.finished_at ?? r.started_at ?? r.created_at)}>{ago(r.finished_at ?? r.started_at ?? r.created_at)}</span>{/snippet}
			{#snippet triggerCell(r: ItemRuns['runs'][number])}<span class="text-muted">{triggerLabels[r.trigger]}</span>{/snippet}
			{#snippet attemptsCell(r: ItemRuns['runs'][number])}<span class="tabular">{r.attempts}</span>{/snippet}
			{#snippet jobCell(r: ItemRuns['runs'][number])}{#if r.job_id}<a class="link" href="/jobs/{r.job_id}">Output{r.exit_code != null ? ` (exit ${r.exit_code})` : ''}</a>{:else}<span class="text-muted">–</span>{/if}{/snippet}
			{#snippet actionCell(r: ItemRuns['runs'][number])}
				{#if runOnce && canReset && r.status !== 'pending'}<Button size="sm" variant="ghost" onclick={() => reset([r.agent_id], false, r.hostname)}>Run again</Button>{/if}
			{/snippet}
			<DataTable
				id="au-runs"
				caption="Runs of {view.name}"
				rows={d.runs}
				key={(r) => r.id}
				scroll={false}
				columns={[
					{ id: 'device', label: 'Device', cell: hostCell, hideable: false },
					{ id: 'status', label: 'State', cell: statusCell, hideable: false },
					...(runOnce ? [] : [{ id: 'trigger', label: 'Fired by', cell: triggerCell, from: 'md' as const }]),
					{ id: 'attempts', label: 'Attempts', cell: attemptsCell, align: 'right' as const, from: 'md' as const },
					{ id: 'when', label: 'When', cell: whenCell, from: 'sm' as const },
					{ id: 'job', label: 'Job', cell: jobCell, from: 'sm' as const },
					...(runOnce && canReset ? [{ id: 'action', label: '', cell: actionCell, class: 'w-28' }] : [])
				] satisfies Column<ItemRuns['runs'][number]>[]}
			>
				{#snippet empty()}
					<EmptyState compact title={filter === 'all' ? 'Nothing has run yet' : `No ${filter} runs`} description={runOnce ? 'Devices get their run within a minute of the automation being enabled or of joining the set.' : 'Runs appear here when the trigger happens on a device.'} />
				{/snippet}
				{#snippet footer()}{#if d.runs.length >= 200}<p class="text-muted px-4 py-2 text-xs">Showing the latest {num(d.runs.length)}.</p>{/if}{/snippet}
			</DataTable>
		{/snippet}
	</Async>
</section>
