<script lang="ts">
	import { CalendarClock, Play, Plus, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, interpreterLabel, osLabels } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { describeCron } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Schedule } from '#lib/types.js';
	import { param, setParams, sortState } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import RunSummary from './RunSummary.svelte';

	const res = resource(() => api.get<Schedule[]>('/schedules'));
	liveReload(() => res.reload(), (e) => e.type === 'jobs' || (e.type === 'job' && !e.output), { debounceMs: 3000, pollMs: 30000 });
	const sort = sortState('name');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const scoped = $derived(currentClient());
	const keyed: Record<string, (s: Schedule) => string | number> = {
		name: (s) => s.name.toLowerCase(),
		script: (s) => s.script_name.toLowerCase(),
		target: (s) => `${s.client_name ?? ''} ${s.site_name ?? ''}`.toLowerCase(),
		next: (s) => (s.enabled && s.next_run_at ? s.next_run_at : '~'),
		last: (s) => s.last_run_at ?? ''
	};
	const rows = $derived.by(() => {
		const f = param('q').toLowerCase();
		const cid = clientId();
		const list = (res.data ?? []).filter((s) => (!f || `${s.name} ${s.script_name}`.toLowerCase().includes(f)) && (!cid || !s.client_id || s.client_id === cid));
		const k = keyed[sort.key] ?? keyed.name;
		const sign = sort.dir === 'asc' ? 1 : -1;
		return [...list].sort((a, b) => (k(a) < k(b) ? -sign : k(a) > k(b) ? sign : 0));
	});
	const mayEdit = (s: Schedule) => (s.client_id ? can('technician') : can('admin'));
	const canCreate = $derived(can('admin') || (can('technician') && clients.list.length > 0));

	async function runNow(s: Schedule) {
		let msg = '';
		const ok = await attempt(async () => {
			const r = await api.post<{ sent: number; queued: number; skipped: number }>(`/schedules/${s.id}/run`);
			msg = `${s.name}: sent to ${r.sent}, queued for ${r.queued} offline${r.skipped ? `, ${r.skipped} still busy with the last run` : ''}.`;
		});
		if (ok) {
			toast.success(msg, { href: { label: 'View runs', href: `/schedules/${s.id}` } });
			res.reload();
		}
	}
</script>

<PageHeader title="Schedules" count={res.data ? rows.length : null} description={scoped ? `MSP-wide schedules, plus schedules for ${scoped.name} only.` : 'Scripts that run on a timetable, on every agent of a client or site.'}>
	{#snippet actions()}
		{#if canCreate}<Button variant="primary" icon={Plus} href={withClient('/schedules/new')}>New schedule</Button>{/if}
	{/snippet}
</PageHeader>

{#if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	{#snippet nameCell(s: Schedule)}
		<a class="hover:text-accent font-medium" href="/schedules/{s.id}">{s.name}</a>
		<div class="text-muted max-w-md truncate text-xs">{describeCron(s.cron)}{s.timezone !== 'UTC' ? ` (${s.timezone})` : ' UTC'}</div>
	{/snippet}
	{#snippet scriptCell(s: Schedule)}<a class="hover:text-accent" href="/scripts/{s.script_id}">{s.script_name}</a><div class="text-muted text-xs">{interpreterLabel(s.interpreter)}</div>{/snippet}
	{#snippet targetCell(s: Schedule)}
		{#if s.client_name}<Badge>{s.client_name}{s.site_name ? ` › ${s.site_name}` : ''}</Badge>{:else}<Badge tone="accent">All clients</Badge>{/if}
		{#if s.os_family}<span class="text-muted ml-1 text-xs">{osLabels[s.os_family]}</span>{/if}
	{/snippet}
	{#snippet nextCell(s: Schedule)}
		{#if !s.enabled}<Badge>Paused</Badge>{:else if s.next_run_at}<span class="whitespace-nowrap" title={datetime(s.next_run_at)}>{datetime(s.next_run_at)}</span>{:else}<span class="text-muted">–</span>{/if}
	{/snippet}
	{#snippet lastCell(s: Schedule)}
		{#if s.last_run_at}<span class="text-muted text-xs whitespace-nowrap" title={datetime(s.last_run_at)}>{ago(s.last_run_at)}</span><RunSummary counts={s.last_run} />{:else}<span class="text-muted">Never</span>{/if}
	{/snippet}
	{#snippet actionCell(s: Schedule)}
		{#if mayEdit(s)}
			<IconButton icon={Play} size="sm" label="Run {s.name} now" class="opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100 [@media(hover:none)]:opacity-100" onclick={() => runNow(s)} />
		{:else}<span class="inline-block size-7" aria-hidden="true"></span>{/if}
	{/snippet}

	<DataTable
		id="schedules"
		caption="Schedules"
		{rows}
		key={(s) => s.id}
		loading={res.loading}
		{sort}
		rowHref={(s) => `/schedules/${s.id}`}
		columns={[
			{ id: 'name', label: 'Schedule', sort: 'name', cell: nameCell, hideable: false },
			{ id: 'script', label: 'Script', sort: 'script', cell: scriptCell, from: 'md' },
			{ id: 'target', label: 'Runs on', sort: 'target', cell: targetCell, from: 'lg' },
			{ id: 'next', label: 'Next run', sort: 'next', cell: nextCell, from: 'sm' },
			{ id: 'last', label: 'Last run', sort: 'last', cell: lastCell },
			{ id: 'actions', label: '', cell: actionCell, hideable: false, align: 'right', class: 'w-12' }
		] satisfies Column<Schedule>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Schedule or script…" aria-label="Search schedules" class="w-full sm:w-64" bind:value={q} />
		{/snippet}
		{#snippet empty()}
			{#if param('q')}
				<EmptyState compact title="No schedules match" />
			{:else}
				<EmptyState icon={CalendarClock} title="No schedules yet" description="Run a saved script on a timetable: nightly cleanups, weekly reports, hourly checks. Each run's output is kept for as long as you choose.">
					{#snippet action()}{#if canCreate}<Button variant="primary" icon={Plus} href={withClient('/schedules/new')}>New schedule</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</DataTable>
{/if}
