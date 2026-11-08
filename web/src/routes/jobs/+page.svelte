<script lang="ts">
	import { RotateCcw, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, ms, num } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import type { Job, Page, Script } from '#lib/types.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import JobBadge from '#lib/components/JobBadge.svelte';
	import { rerun } from '#lib/jobs.js';

	const sort = sortState('created', 'desc');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});

	const statuses = { '': 'All', 'queued,sent': 'Running', succeeded: 'Succeeded', failed: 'Failed', 'expired,cancelled': 'Expired' } as const;
	const status = $derived(param('status') in statuses ? param('status') : '');

	const list = paged<Job>(() =>
		`/jobs${qs({ status, script_id: param('script'), client_id: clientId(), q: param('q'), sort: sort.key, dir: sort.dir })}`
	);
	liveReload(() => list.reload(), (e) => (e.type === 'job' && !e.output) || e.type === 'jobs', { debounceMs: 1000 });

	// A count for every status view, under the other filters (client, script, search).
	const statusCounts = resource(async () => {
		const base = { script_id: param('script'), client_id: clientId(), q: param('q'), limit: 1 };
		const keys = Object.keys(statuses);
		const pages = await Promise.all(keys.map((k) => api.get<Page<Job>>(`/jobs${qs({ status: k, ...base })}`)));
		return Object.fromEntries(keys.map((k, i) => [k, `${num(pages[i].total)}${pages[i].total_exact ? '' : '+'}`])) as Record<string, string>;
	});
	liveReload(() => statusCounts.reload(), (e) => (e.type === 'job' && !e.output) || e.type === 'jobs', { debounceMs: 1500 });

	const scripts = resource(() => api.get<Script[]>('/scripts'));
	const scriptItems = $derived((scripts.data ?? []).map((s) => ({ value: s.id, label: s.name, hint: s.client_name ?? undefined })));
	let scriptFilter = $state(param('script'));
	const scoped = $derived(currentClient());
	const finished = (j: Job) => !['queued', 'sent'].includes(j.status);
</script>

<PageHeader title="Jobs" count={list.data ? `${list.data.total}${list.data.total_exact ? '' : '+'}` : null} description={scoped ? `Scripts run on ${scoped.name}'s agents.` : undefined} />

<Tabs
	label="Status"
	class="mb-3"
	value={status}
	onchange={(v) => setParams({ status: v || null })}
	items={Object.entries(statuses).map(([value, label]) => ({ value, label, count: statusCounts.data?.[value] }))}
/>

{#if list.error && !list.data}
	<div class="card"><ErrorState error={list.error} onretry={() => list.reload()} /></div>
{:else}
	{#snippet createdCell(j: Job)}<a class="hover:text-accent whitespace-nowrap" href="/jobs/{j.id}" title={datetime(j.created_at)}>{ago(j.created_at)}</a>{/snippet}
	{#snippet agentCell(j: Job)}<a class="hover:text-accent font-medium" href="/agents/{j.agent_id}">{j.hostname}</a>{/snippet}
	{#snippet scriptCell(j: Job)}<span class="block max-w-xs truncate">{j.script_name ?? `Ad-hoc ${j.interpreter}`}</span>{/snippet}
	{#snippet statusCell(j: Job)}<JobBadge status={j.status} />{/snippet}
	{#snippet exitCell(j: Job)}{#if j.exit_code != null}{j.exit_code}{:else}<span class="text-muted" aria-label="none">–</span>{/if}{/snippet}
	{#snippet durCell(j: Job)}{#if j.duration_ms != null}{ms(j.duration_ms)}{:else}<span class="text-muted" aria-label="none">–</span>{/if}{/snippet}
	{#snippet byCell(j: Job)}<span class="text-muted">{j.created_by_name ?? '–'}</span>{/snippet}
	{#snippet actionCell(j: Job)}
		{#if can('technician') && finished(j)}
			<!-- Quiet until the row is hovered or focused; always there on touch screens. -->
			<IconButton
				icon={RotateCcw}
				size="sm"
				label="Rerun on {j.hostname}"
				class="opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100 [@media(hover:none)]:opacity-100"
				onclick={() => rerun(j.id, { open: false })}
			/>
		{:else}
			<span class="inline-block size-7" aria-hidden="true"></span>
		{/if}
	{/snippet}

	<DataTable
		id="jobs"
		caption="Jobs"
		activeFilters={param('script') ? 1 : 0}
		rows={list.rows}
		key={(j) => j.id}
		loading={list.loading}
		busy={list.busy}
		{sort}
		rowHref={(j) => `/jobs/${j.id}`}
		columns={[
			{ id: 'created', label: 'Created', sort: 'created', cell: createdCell, hideable: false },
			{ id: 'agent', label: 'Agent', sort: 'hostname', cell: agentCell },
			{ id: 'script', label: 'Script', sort: 'script', cell: scriptCell, from: 'sm' },
			{ id: 'status', label: 'Status', sort: 'status', cell: statusCell },
			{ id: 'exit', label: 'Exit', cell: exitCell, align: 'right', from: 'md' },
			{ id: 'duration', label: 'Duration', sort: 'duration', cell: durCell, align: 'right', from: 'md' },
			{ id: 'by', label: 'By', cell: byCell, from: 'lg' },
			{ id: 'actions', label: '', cell: actionCell, hideable: false, align: 'right', class: 'w-12' }
		] satisfies Column<Job>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Agent or script…" aria-label="Search jobs" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			<Combobox bind:value={scriptFilter} items={scriptItems} label="Script" placeholder="Any script" clearable class="w-full sm:w-56" onchange={(v) => setParams({ script: v || null })} />
		{/snippet}
		{#snippet empty()}
			<EmptyState
				title={status || param('q') || param('script') ? 'No jobs match' : 'No jobs yet'}
				description={status || param('q') || param('script') ? 'Try another status or clear the search.' : 'Run a script from an agent, the Agents list, or the command palette (Ctrl K).'}
			/>
		{/snippet}
		{#snippet footer()}
			{#if list.data}
				<Pagination
					shown={list.rows.length}
					total={list.data.total}
					exact={list.data.total_exact}
					hasPrev={!!list.data.prev}
					hasNext={!!list.data.next}
					pageSize={list.pageSize}
					onprev={list.prev}
					onnext={list.next}
					onfirst={list.first}
					onpagesize={list.setPageSize}
				/>
			{/if}
		{/snippet}
	</DataTable>
{/if}
