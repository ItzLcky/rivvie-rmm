<script lang="ts">
	import { CloudDownload, Play, Plus, Search, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, num, plural } from '#lib/format.js';
	import { liveReload, onLive } from '#lib/live.svelte.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import type { AgentSummary, Page, Release } from '#lib/types.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import HealthBadge from '#lib/components/HealthBadge.svelte';
	import OsBadge from '#lib/components/OsBadge.svelte';
	import RunScript from '#lib/components/RunScript.svelte';
	import Status from '#lib/components/Status.svelte';
	import UsageBar from '#lib/components/UsageBar.svelte';

	// Built-in views are presets over the same filters.
	const views = {
		all: {},
		online: { online: true },
		offline: { online: false },
		attention: { health: 'attention,unhealthy' },
		new: { new_days: 7 }
	} as const;
	type View = keyof typeof views;
	const view = $derived((param('view', 'all') in views ? param('view', 'all') : 'all') as View);
	const sort = sortState('hostname');

	// The search box updates the URL as you type (debounced), so the view is shareable.
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});

	const list = paged<AgentSummary>(() =>
		`/agents${qs({
			...views[view],
			client_id: clientId(),
			site_id: param('site'),
			os: param('os'),
			health: param('health') || (views[view] as { health?: string }).health,
			q: param('q'),
			sort: sort.key,
			dir: sort.dir
		})}`
	);

	// Online/offline flips change which rows match: refetch. Metrics only update rows in place.
	liveReload(() => list.reload(), (e) => e.type === 'agent' && !e.last_metrics && view !== 'all', { debounceMs: 1500 });
	onLive((e) => {
		if (e.type !== 'agent') return;
		const row = list.data?.items.find((a) => a.id === e.id);
		if (!row) return;
		row.online = e.online;
		if (e.last_metrics) row.last_metrics = e.last_metrics;
		if (!e.online) row.last_seen_at = new Date().toISOString();
	});

	let selected = $state(new Set<string>());
	// Remember the selected rows (not just ids) across pages, for Run script.
	const picked = new Map<string, AgentSummary>();
	$effect(() => {
		for (const a of list.rows) if (selected.has(a.id)) picked.set(a.id, a);
		for (const id of [...picked.keys()]) if (!selected.has(id)) picked.delete(id);
	});
	let running = $state(false);
	/** Every agent matching the filters, remembered for Run script. */
	async function selectAll() {
		const all = await list.all();
		for (const a of all) picked.set(a.id, a);
		return all.map((a) => a.id);
	}

	const releases = resource(() => (can('admin') ? api.get<{ releases: Release[] }>('/agent-updates').then((r) => r.releases) : Promise.resolve([])));
	const outdated = $derived((releases.data ?? []).reduce((n, r) => n + r.outdated, 0));
	async function rollout(ids: string[] | null) {
		const what = ids ? plural(ids.length, 'selected agent') : `every online agent (${outdated} out of date)`;
		const ok = await confirmAction({
			title: 'Update agents?',
			message: `Offer the latest signed release to ${what}. Each agent waits for its running jobs, restarts, and rolls back by itself if the new version can't reconnect.`,
			confirmLabel: 'Update'
		});
		if (!ok) return;
		await attempt(async () => {
			const r = await api.post<{ offered: number; skipped: number }>('/agent-updates/rollout', { agent_ids: ids });
			toast.success(`Update offered to ${plural(r.offered, 'agent')}; ${r.skipped} skipped (already current, or no release for their platform).`);
		});
	}

	const scoped = $derived(currentClient());
	const sites = $derived(scoped?.sites ?? []);
	// A count for every view, under the other filters (client, site, OS, search): one cheap
	// limit=1 request each, refreshed when agents go online or offline.
	const viewCounts = resource(async () => {
		const base = { client_id: clientId(), site_id: param('site'), os: param('os'), q: param('q'), limit: 1 };
		const keys = Object.keys(views) as View[];
		const pages = await Promise.all(keys.map((k) => api.get<Page<AgentSummary>>(`/agents${qs({ ...views[k], ...base })}`)));
		return Object.fromEntries(keys.map((k, i) => [k, `${num(pages[i].total)}${pages[i].total_exact ? '' : '+'}`])) as Record<View, string>;
	});
	liveReload(() => viewCounts.reload(), (e) => e.type === 'agent' && !e.last_metrics, { debounceMs: 1500 });
	const filtered = $derived(!!(param('q') || param('os') || param('site') || param('health') || view !== 'all'));
</script>

<PageHeader
	title="Agents"
	count={list.data ? list.data.total : null}
	menu={can('admin') && outdated > 0 ? [{ label: `Update ${outdated} outdated agent${outdated === 1 ? '' : 's'}`, icon: CloudDownload, onSelect: () => rollout(null) }] : undefined}
>
	{#snippet actions()}
		{#if can('technician')}<Button icon={Plus} href={withClient('/clients')}>Enroll</Button>{/if}
	{/snippet}
</PageHeader>

<Tabs
	label="View"
	class="mb-3"
	value={view}
	onchange={(v) => setParams({ view: v === 'all' ? null : v, health: null })}
	items={[
		{ value: 'all', label: 'All', count: viewCounts.data?.all },
		{ value: 'online', label: 'Online', count: viewCounts.data?.online },
		{ value: 'offline', label: 'Offline', count: viewCounts.data?.offline },
		{ value: 'attention', label: 'Needs attention', count: viewCounts.data?.attention },
		{ value: 'new', label: 'New', count: viewCounts.data?.new, title: 'Enrolled in the last 7 days' }
	]}
/>

{#if list.error && !list.data}
	<div class="card"><ErrorState error={list.error} onretry={() => list.reload()} /></div>
{:else}
	{#snippet hostCell(a: AgentSummary)}
		<a class="hover:text-accent font-medium whitespace-nowrap" href="/agents/{a.id}">{a.hostname}</a>
		<!-- Phones: the stacked cell carries client/site and status. -->
		<div class="text-muted mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs md:hidden">
			<Status online={a.online} /><span class="truncate">{scoped ? a.site_name : `${a.client_name} › ${a.site_name}`}</span>
			{#if a.health === 'attention' || a.health === 'unhealthy'}<span class="sm:hidden"><HealthBadge health={a.health} agent={a} /></span>{/if}
		</div>
	{/snippet}
	{#snippet clientCell(a: AgentSummary)}
		<span class="text-muted inline-flex items-center gap-1 whitespace-nowrap">{#if !scoped}<a class="hover:text-fg" href={withClient('/agents', a.client_id)}>{a.client_name}</a><span class="text-subtle" aria-hidden="true">›</span>{/if}<span>{a.site_name}</span></span>
	{/snippet}
	{#snippet osCell(a: AgentSummary)}<OsBadge os={a.os_family} name={a.os_name} muted />{/snippet}
	{#snippet statusCell(a: AgentSummary)}<Status online={a.online} />{/snippet}
	{#snippet healthCell(a: AgentSummary)}<HealthBadge health={a.health} agent={a} />{/snippet}
	{#snippet cpuCell(a: AgentSummary)}{#if a.last_metrics && a.online}<UsageBar bar={false} value={a.last_metrics.cpu_percent} />{:else}<span class="text-muted" aria-label="no data">–</span>{/if}{/snippet}
	{#snippet memCell(a: AgentSummary)}{#if a.last_metrics}<UsageBar bar={false} value={a.last_metrics.mem_total ? (100 * a.last_metrics.mem_used) / a.last_metrics.mem_total : 0} />{:else}<span class="text-muted" aria-label="no data">–</span>{/if}{/snippet}
	{#snippet diskCell(a: AgentSummary)}{#if a.last_metrics}<UsageBar bar={false} value={a.disk_max_pct} />{:else}<span class="text-muted" aria-label="no data">–</span>{/if}{/snippet}
	{#snippet seenCell(a: AgentSummary)}<span class="text-muted whitespace-nowrap">{a.online ? 'now' : ago(a.last_seen_at)}</span>{/snippet}
	{#snippet versionCell(a: AgentSummary)}<span class="text-muted font-mono text-[13px]">{a.agent_version}</span>{/snippet}
	{#snippet enrolledCell(a: AgentSummary)}<span class="text-muted">{ago(a.enrolled_at)}</span>{/snippet}

	<DataTable
		id="agents"
		caption="Agents"
		activeFilters={[param('site'), param('os'), param('health')].filter(Boolean).length}
		rows={list.rows}
		key={(a) => a.id}
		loading={list.loading}
		busy={list.busy}
		{sort}
		bind:selected
		matching={list.data ? { total: list.data.total, exact: list.data.total_exact, select: selectAll } : undefined}
		rowHref={(a) => `/agents/${a.id}`}
		columns={[
			{ id: 'hostname', label: 'Hostname', sort: 'hostname', cell: hostCell, hideable: false },
			{ id: 'client', label: scoped ? 'Site' : 'Client / site', sort: 'client', cell: clientCell, from: 'md' },
			{ id: 'os', label: 'OS', sort: 'os', cell: osCell, from: 'lg' },
			{ id: 'status', label: 'Status', sort: 'status', cell: statusCell, from: 'md' },
			{ id: 'health', label: 'Health', sort: 'health', cell: healthCell, from: 'sm' },
			{ id: 'cpu', label: 'CPU', sort: 'cpu', cell: cpuCell, align: 'right', from: 'xl' },
			{ id: 'mem', label: 'Memory', sort: 'mem', cell: memCell, align: 'right', from: 'xl' },
			{ id: 'disk', label: 'Disk', sort: 'disk', cell: diskCell, align: 'right', from: 'lg' },
			{ id: 'last_seen', label: 'Last seen', sort: 'last_seen', cell: seenCell, align: 'right', from: 'md' },
			{ id: 'version', label: 'Agent version', sort: 'version', cell: versionCell, defaultHidden: true },
			{ id: 'enrolled', label: 'Enrolled', sort: 'enrolled', cell: enrolledCell, defaultHidden: true }
		] satisfies Column<AgentSummary>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Hostname, IP, user…" aria-label="Search agents" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			{#if sites.length > 1}
				<Select
					aria-label="Site"
					class="w-full sm:w-auto"
					value={param('site')}
					onchange={(e) => setParams({ site: e.currentTarget.value })}
					options={[{ value: '', label: 'All sites' }, ...sites.map((s) => ({ value: s.id, label: s.name }))]}
				/>
			{/if}
			<Select
				aria-label="Operating system"
				class="w-full sm:w-auto"
				value={param('os')}
				onchange={(e) => setParams({ os: e.currentTarget.value })}
				options={[
					{ value: '', label: 'Any OS' },
					{ value: 'windows', label: 'Windows' },
					{ value: 'linux', label: 'Linux' },
					{ value: 'macos', label: 'macOS' }
				]}
			/>
			{#if param('health')}
				<Button size="sm" variant="ghost" iconRight={X} onclick={() => setParams({ health: null })}>Health: {param('health').replace(',', ', ')}</Button>
			{/if}
		{/snippet}
		{#snippet bulk(n)}
			{#if can('technician')}<Button size="sm" variant="primary" icon={Play} onclick={() => (running = true)}>Run script</Button>{/if}
			{#if can('admin') && outdated > 0}<Button size="sm" icon={CloudDownload} onclick={() => rollout([...selected])}>Update agent{n === 1 ? '' : 's'}</Button>{/if}
		{/snippet}
		{#snippet empty()}
			{#if filtered}
				<EmptyState title="No agents match" description="Try another view or clear the filters.">
					{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, os: null, site: null, health: null, view: null }); }}>Clear filters</Button>{/snippet}
				</EmptyState>
			{:else}
				<EmptyState title={scoped ? `No agents for ${scoped.name} yet` : 'No agents yet'} description="Create an enrollment token for a site and run the install command on each machine.">
					{#snippet action()}{#if can('technician')}<Button size="sm" variant="primary" icon={Plus} href={withClient('/clients')}>Enroll agents</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
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

{#if running}
	<RunScript agents={[...picked.values()]} onclose={() => (running = false)} />
{/if}
