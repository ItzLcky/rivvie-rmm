<script lang="ts">
	import { page } from '$app/state';
	import { Pencil, Play } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, interpreterLabel, ms, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { describeCron } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Job, Page, Schedule } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';
	import RunSummary from '../RunSummary.svelte';

	/** A scheduled script and its runs. It's edited in its policy set. */
	const id = $derived(page.params.id!);
	const res = resource(() => api.get<Schedule>(`/schedules/${id}`), { keep: false });
	const runs = resource(() => api.get<Page<Job>>(`/jobs?schedule_id=${id}&limit=100`));
	liveReload(() => runs.reload(), (e) => e.type === 'job' && !e.output, { debounceMs: 1500 });
	const editHref = (s: Schedule) => `/policies/sets/${s.set_id}?section=schedules&item=${s.id}`;
	const mayRun = (s: Schedule) => (s.client_id ? can('technician') : can('admin'));

	async function runNow(s: Schedule) {
		await attempt(async () => {
			const r = await api.post<{ sent: number; queued: number; skipped: number }>(`/schedules/${s.id}/run`);
			toast.success(`Sent to ${r.sent}, queued for ${r.queued} offline${r.skipped ? `, skipped ${r.skipped} still busy with the last run` : ''}.`);
			runs.reload();
		});
	}
</script>

<svelte:head><title>{res.data?.name ?? 'Schedule'}</title></svelte:head>

<Async {res}>
	{#snippet skeleton()}
		<div class="mb-4 space-y-2"><Skeleton class="h-3 w-24" /><Skeleton class="h-7 w-64" /></div>
		<div class="card space-y-3 p-4"><Skeleton lines={6} /></div>
	{/snippet}
	{#snippet children(s)}
		<PageHeader title={s.name} crumbs={[{ label: 'Schedules', href: '/schedules' }, { label: s.name }]}>
			{#snippet meta()}
				{#if !s.enabled}<Badge>Paused</Badge>{:else if s.next_run_at}<span class="text-muted text-xs">Next run {datetime(s.next_run_at)}</span>{/if}
			{/snippet}
			{#snippet actions()}
				{#if mayRun(s)}<Button icon={Play} onclick={() => runNow(s)}>Run now</Button>{/if}
				<Button variant="primary" icon={Pencil} href={editHref(s)}>Edit in {s.set_name}</Button>
			{/snippet}
		</PageHeader>

		<section class="card mb-6 max-w-4xl p-4" aria-label="Schedule">
			<dl class="dl">
				<dt>Script</dt><dd><a class="link" href="/scripts/{s.script_id}">{s.script_name}</a> <span class="text-muted text-xs">{interpreterLabel(s.interpreter)}</span></dd>
				{#if s.args.length}<dt>Arguments</dt><dd class="font-mono text-[13px]">{s.args.join(' ')}</dd>{/if}
				<dt>When</dt><dd>{describeCron(s.cron)} <span class="text-muted">({s.timezone})</span> <code class="text-muted ml-1 text-xs">{s.cron}</code></dd>
				<dt>Policy set</dt>
				<dd>
					<a class="link" href={editHref(s)}>{s.set_name}</a>
					<span class="text-muted block text-xs">Runs on the devices using it or a set below it{s.client_name ? `, of ${s.client_name}${s.site_name ? ` › ${s.site_name}` : ''} only` : ''}: {plural(s.agents, 'device')} now. Sets below can change its arguments and timeout, or switch it off.</span>
				</dd>
				<dt>Timeout</dt><dd>{s.timeout_secs ? `${s.timeout_secs} s` : 'The script’s own'}</dd>
				<dt>Keeps runs</dt><dd>{plural(s.retain_days, 'day')}</dd>
				<dt>Last run</dt><dd>{#if s.last_run_at}{ago(s.last_run_at)} <RunSummary counts={s.last_run} />{:else}<span class="text-muted">Never</span>{/if}</dd>
			</dl>
		</section>

		{#snippet whenCell(j: Job)}<a class="hover:text-accent whitespace-nowrap" href="/jobs/{j.id}" title={datetime(j.created_at)}>{ago(j.created_at)}</a>{/snippet}
		{#snippet agentCell(j: Job)}<a class="hover:text-accent font-medium" href="/agents/{j.agent_id}">{j.hostname}</a>{/snippet}
		{#snippet statusCell(j: Job)}<JobBadge status={j.status} />{/snippet}
		{#snippet durCell(j: Job)}{#if j.duration_ms != null}{ms(j.duration_ms)}{:else}<span class="text-muted" aria-label="none">–</span>{/if}{/snippet}
		<h2 class="mb-2 panel-title">Recent runs</h2>
		<DataTable
			id="schedule-runs"
			caption="Recent runs"
			rows={runs.data?.items ?? []}
			key={(j) => j.id}
			loading={runs.loading}
			rowHref={(j) => `/jobs/${j.id}`}
			scroll={false}
			columns={[
				{ id: 'created', label: 'Started', cell: whenCell, hideable: false },
				{ id: 'agent', label: 'Agent', cell: agentCell },
				{ id: 'status', label: 'Status', cell: statusCell },
				{ id: 'duration', label: 'Duration', cell: durCell, align: 'right', from: 'sm' }
			] satisfies Column<Job>[]}
		>
			{#snippet empty()}<EmptyState compact title="No runs yet" description={s.enabled && s.next_run_at ? `The first run is ${datetime(s.next_run_at)}.` : undefined} />{/snippet}
			{#snippet footer()}{#if runs.data?.next}<p class="text-muted px-3 py-2 text-xs">Showing the latest 100. <a class="link" href="/jobs?q={encodeURIComponent(s.script_name)}">See all in Jobs</a></p>{/if}{/snippet}
		</DataTable>
	{/snippet}
</Async>
