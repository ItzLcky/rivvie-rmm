<script lang="ts">
	import { BellRing, Check, CheckCheck, Search, ShieldCheck } from '@lucide/svelte';
	import { ago, datetime, num, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { acknowledge, alertCounts, resolve } from '#lib/monitoring/alerts.svelte.js';
	import { kindLabels } from '#lib/monitoring/labels.js';
	import { inBatches, paged } from '#lib/paged.svelte.js';
	import { clientId, currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Alert, PolicyKind } from '#lib/types.js';
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
	import AlertStateBadge from '#lib/components/AlertStateBadge.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';
	import MaintenanceWindows from '#lib/components/MaintenanceWindows.svelte';
	import OnCallChip from '#lib/oncall/OnCallChip.svelte';

	const sort = sortState('opened', 'desc');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const views = { active: 'Active', open: 'Open', acknowledged: 'Acknowledged', resolved: 'Resolved', all: 'All' } as const;
	const view = $derived(param('state') in views ? param('state') : 'active');
	const severity = $derived(param('severity'));
	const kind = $derived(param('kind'));

	const list = paged<Alert>(() =>
		`/alerts${qs({ state: view, severity, kind, policy_id: param('policy'), agent_id: param('agent'), client_id: clientId(), q: param('q'), sort: sort.key, dir: sort.dir })}`
	);
	liveReload(() => list.reload(), (e) => e.type === 'alert', { debounceMs: 1000 });

	let selected = $state(new Set<string>());
	const scoped = $derived(currentClient());
	const filtered = $derived(!!(param('q') || severity || kind || param('policy') || param('agent')));

	async function apply(action: 'acknowledge' | 'resolve') {
		const ids = [...selected];
		// The bulk endpoint takes 1000 at a time.
		const ok = await attempt(
			() => inBatches(ids, 1000, (slice) => (action === 'acknowledge' ? acknowledge(slice) : resolve(slice))),
			action === 'acknowledge' ? `Acknowledged ${plural(ids.length, 'alert')}.` : `Resolved ${plural(ids.length, 'alert')}.`
		);
		if (ok) {
			selected = new Set();
			list.reload();
		}
	}
</script>

<PageHeader
	title="Alerts"
	count={list.data ? `${list.data.total}${list.data.total_exact ? '' : '+'}` : null}
	description={scoped ? `Alerts on ${scoped.name}'s agents.` : 'Raised by alert policies. Conditions clear by themselves; acknowledge to show someone is on it.'}
>
	{#snippet actions()}<Button icon={ShieldCheck} href={withClient('/policies')}>Policies</Button>{/snippet}
</PageHeader>

<div class="mb-3"><OnCallChip /></div>

<Tabs
	label="State"
	class="mb-3"
	value={view}
	onchange={(v) => setParams({ state: v === 'active' ? null : v })}
	items={Object.entries(views).map(([value, label]) => ({ value, label, count: value === 'active' && alertCounts.loaded && !scoped ? num(alertCounts.critical + alertCounts.warning + alertCounts.info) : undefined }))}
/>

{#if list.error && !list.data}
	<div class="card"><ErrorState error={list.error} onretry={() => list.reload()} /></div>
{:else}
	{#snippet sevCell(a: Alert)}<SeverityBadge severity={a.severity} />{/snippet}
	{#snippet titleCell(a: Alert)}
		<a class="hover:text-accent font-medium" href="/alerts/{a.id}">{a.title}</a>
		<div class="text-muted max-w-md truncate text-xs"><span class="sm:hidden">{a.hostname} · {a.severity} · {ago(a.opened_at)}</span><span class="hidden sm:inline">{a.policy_name ?? kindLabels[a.kind]}</span>{a.occurrences > 1 ? ` · ${num(a.occurrences)} times` : ''}</div>
	{/snippet}
	{#snippet agentCell(a: Alert)}
		{#if a.device_id}
			<a class="hover:text-accent font-medium" href="/network/devices/{a.device_id}">{a.device_name ?? 'Network device'}</a>
			<div class="text-muted truncate text-xs">{a.client_name} › {a.site_name} · read by {a.hostname}</div>
		{:else}
			<a class="hover:text-accent font-medium" href="/agents/{a.agent_id}?tab=alerts">{a.hostname}</a>
			<div class="text-muted truncate text-xs">{a.client_name} › {a.site_name}</div>
		{/if}
	{/snippet}
	{#snippet stateCell(a: Alert)}<AlertStateBadge alert={a} />{/snippet}
	{#snippet openedCell(a: Alert)}<span class="whitespace-nowrap" title={datetime(a.opened_at)}>{ago(a.opened_at)}</span>{/snippet}
	{#snippet seenCell(a: Alert)}<span class="text-muted whitespace-nowrap" title={datetime(a.resolved_at ?? a.last_seen_at)}>{a.resolved_at ? `resolved ${ago(a.resolved_at)}` : ago(a.last_seen_at)}</span>{/snippet}

	<DataTable
		id="alerts"
		caption="Alerts"
		activeFilters={(severity ? 1 : 0) + (kind ? 1 : 0)}
		rows={list.rows}
		key={(a) => a.id}
		loading={list.loading}
		busy={list.busy}
		{sort}
		bind:selected={() => (can('technician') ? selected : undefined), (v) => (selected = v ?? new Set())}
		matching={list.data ? { total: list.data.total, exact: list.data.total_exact, select: async () => (await list.all()).map((a) => a.id) } : undefined}
		rowHref={(a) => `/alerts/${a.id}`}
		columns={[
			{ id: 'severity', label: 'Severity', sort: 'severity', cell: sevCell, class: 'w-28', from: 'sm' },
			{ id: 'title', label: 'Alert', sort: 'title', cell: titleCell, hideable: false },
			{ id: 'agent', label: 'Agent', sort: 'hostname', cell: agentCell, from: 'sm' },
			{ id: 'state', label: 'State', cell: stateCell, from: 'md' },
			{ id: 'opened', label: 'Opened', sort: 'opened', cell: openedCell, from: 'sm' },
			{ id: 'last_seen', label: 'Last seen', sort: 'last_seen', cell: seenCell, from: 'lg' }
		] satisfies Column<Alert>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Agent or alert…" aria-label="Search alerts" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			<Select aria-label="Severity" class="w-full sm:w-auto" value={severity} onchange={(e) => setParams({ severity: e.currentTarget.value })} options={[{ value: '', label: 'Any severity' }, { value: 'critical', label: 'Critical' }, { value: 'warning', label: 'Warning' }, { value: 'info', label: 'Info' }]} />
			<Select aria-label="Type" class="w-full sm:w-auto" value={kind} onchange={(e) => setParams({ kind: e.currentTarget.value })} options={[{ value: '', label: 'Any type' }, ...Object.entries(kindLabels).map(([value, label]) => ({ value, label }))]} />
			{#if param('policy') || param('agent')}<Button size="sm" onclick={() => setParams({ policy: null, agent: null })}>Clear {param('policy') ? 'policy' : 'agent'} filter</Button>{/if}
		{/snippet}
		{#snippet bulk(n)}
			<Button size="sm" icon={Check} onclick={() => apply('acknowledge')}>Acknowledge {n}</Button>
			<Button size="sm" icon={CheckCheck} onclick={() => apply('resolve')}>Resolve {n}</Button>
		{/snippet}
		{#snippet empty()}
			{#if filtered || view === 'resolved'}
				<EmptyState compact title="No alerts match" />
			{:else if view === 'active' || view === 'open'}
				<EmptyState icon={BellRing} title="All clear" description="No open alerts. Policies decide what raises one: offline agents, CPU, memory, disk, services, failed jobs and log entries.">
					{#snippet action()}<Button href={withClient('/policies')} icon={ShieldCheck}>Policies</Button>{/snippet}
				</EmptyState>
			{:else}
				<EmptyState compact title="No alerts yet" />
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

<MaintenanceWindows />
