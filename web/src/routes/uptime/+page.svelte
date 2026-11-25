<script lang="ts">
	import { Activity, BellRing, CircleHelp, Plus, Search } from '@lucide/svelte';
	import { goto } from '$app/navigation';
	import { api } from '#lib/api.js';
	import MonitorDrawer from '#lib/components/uptime/MonitorDrawer.svelte';
	import { ago, datetime, ms } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import { certDays, monitorKindLabel, monitorKinds, monitorLabel, monitorTone, uptimePct, type Monitor, type UptimeSummary } from '#lib/uptime.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Stat from '#lib/ui/Stat.svelte';

	const scoped = $derived(currentClient());
	const sort = sortState('state');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const summary = resource(() => api.get<UptimeSummary>(`/uptime/summary${qs({ client_id: clientId() })}`));
	const monitors = resource(() => api.get<Monitor[]>(`/uptime/monitors${qs({ client_id: clientId(), site_id: param('site'), state: param('state'), kind: param('kind'), q: param('q') })}`));
	liveReload(() => { monitors.reload(); summary.reload(); }, (e) => e.type === 'alert' || e.type === 'monitor', { debounceMs: 2000, pollMs: 30000 });
	let adding = $state(false);

	const keys: Record<string, (m: Monitor) => string | number | null> = {
		name: (m) => m.name.toLowerCase(), state: (m) => (m.enabled ? ({ down: 0, unknown: 1, up: 2 })[m.state] : 3), kind: (m) => m.kind, target: (m) => m.target,
		site: (m) => `${m.client_name} ${m.site_name}`, uptime: (m) => m.uptime_30d, latency: (m) => m.last_ms, checked: (m) => m.last_at, cert: (m) => m.cert_not_after
	};
	const rows = $derived.by(() => {
		const get = keys[sort.key] ?? keys.state;
		const dir = sort.dir === 'desc' ? -1 : 1;
		return [...(monitors.data ?? [])].sort((a, b) => {
			const x = get(a) ?? '';
			const y = get(b) ?? '';
			return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })) * dir || a.name.localeCompare(b.name);
		});
	});
	const sites = $derived(scoped?.sites ?? []);
	const s = $derived(summary.data);
</script>

<PageHeader title="Uptime" description="Websites, ports, hosts, certificates and DNS names, checked on a schedule by an agent on the network.">
	{#snippet actions()}
		{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (adding = true)}>Add monitor</Button>{/if}
	{/snippet}
</PageHeader>

<div class="mb-5 grid gap-3 sm:grid-cols-3">
	<Stat label="Monitors" value={s?.monitors ?? 0} icon={Activity} href="/uptime" />
	<Stat label="Down" value={s?.down ?? 0} tone="danger" icon={BellRing} href="/uptime?state=down" />
	<Stat label="Unknown" value={s?.unknown ?? 0} tone="warning" icon={CircleHelp} href="/uptime?state=unknown" />
</div>
{#if s?.uptime_30d != null}<p class="text-muted -mt-2 mb-4 text-sm">{uptimePct(s.uptime_30d)} of checks passed in the last 30 days.</p>{/if}

{#if monitors.error && !monitors.data}
	<div class="card"><ErrorState error={monitors.error} onretry={() => monitors.reload()} /></div>
{:else}
	{#snippet nameCell(m: Monitor)}
		<a class="hover:text-accent font-medium whitespace-nowrap" href="/uptime/{m.id}">{m.name}</a>
		<div class="text-muted mt-0.5 max-w-72 truncate font-mono text-xs">{m.target}</div>
	{/snippet}
	{#snippet stateCell(m: Monitor)}
		<Badge tone={m.enabled ? monitorTone[m.state] : 'neutral'}>{m.enabled ? monitorLabel[m.state] : 'Off'}</Badge>
		{#if m.enabled && m.state !== 'up'}<div class="text-muted mt-0.5 text-xs whitespace-nowrap" title={datetime(m.state_since)}>{ago(m.state_since)}</div>{/if}
	{/snippet}
	{#snippet kindCell(m: Monitor)}<span class="whitespace-nowrap">{monitorKindLabel(m.kind)}</span>{/snippet}
	{#snippet siteCell(m: Monitor)}<span class="text-muted whitespace-nowrap">{scoped ? m.site_name : `${m.client_name} › ${m.site_name}`}</span>{/snippet}
	{#snippet uptimeCell(m: Monitor)}<span class="tabular whitespace-nowrap" title="Last 24 hours: {uptimePct(m.uptime_24h)}">{uptimePct(m.uptime_30d)}</span>{/snippet}
	{#snippet latencyCell(m: Monitor)}<span class="tabular text-muted whitespace-nowrap">{m.last_ms != null && m.state === 'up' ? ms(m.last_ms) : '–'}</span>{/snippet}
	{#snippet certCell(m: Monitor)}
		{@const d = certDays(m.cert_not_after)}
		{#if d == null}<span class="text-muted">–</span>{:else}<Badge tone={d < 0 ? 'danger' : d <= 14 ? 'warning' : 'neutral'}>{d < 0 ? 'Expired' : `${d} days`}</Badge>{/if}
	{/snippet}
	{#snippet checkedCell(m: Monitor)}
		<span class="text-muted whitespace-nowrap" title={m.last_message ?? ''}>{m.last_at ? ago(m.last_at) : 'never'}</span>
		<div class="text-muted text-xs whitespace-nowrap">{m.runner === 'server' ? 'the server' : (m.runner_hostname ?? 'no agent')}{m.runner_hostname && !m.runner_online ? ' (offline)' : ''}</div>
	{/snippet}

	<DataTable
		id="uptime-monitors"
		caption="Uptime monitors"
		activeFilters={[param('site'), param('state'), param('kind')].filter(Boolean).length}
		{rows}
		key={(m) => m.id}
		loading={monitors.loading && !monitors.data}
		{sort}
		rowHref={(m) => `/uptime/${m.id}`}
		columns={[
			{ id: 'name', label: 'Monitor', sort: 'name', cell: nameCell, hideable: false },
			{ id: 'state', label: 'State', sort: 'state', cell: stateCell },
			{ id: 'kind', label: 'Kind', sort: 'kind', cell: kindCell, from: 'md' },
			{ id: 'site', label: scoped ? 'Site' : 'Client / site', sort: 'site', cell: siteCell, from: 'lg' },
			{ id: 'uptime', label: '30 days', sort: 'uptime', cell: uptimeCell, align: 'right', from: 'sm' },
			{ id: 'latency', label: 'Response', sort: 'latency', cell: latencyCell, align: 'right', from: 'lg' },
			{ id: 'cert', label: 'Certificate', sort: 'cert', cell: certCell, from: 'xl' },
			{ id: 'checked', label: 'Last check', sort: 'checked', cell: checkedCell, align: 'right', from: 'md' }
		] satisfies Column<Monitor>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Name, address or client…" aria-label="Search monitors" class="min-w-0 flex-1 sm:w-64 sm:flex-none" bind:value={q} />
		{/snippet}
		{#snippet filters()}
			{#if sites.length > 1}
				<Select aria-label="Site" class="w-full sm:w-auto" value={param('site')} onchange={(e) => setParams({ site: e.currentTarget.value })} options={[{ value: '', label: 'All sites' }, ...sites.map((x) => ({ value: x.id, label: x.name }))]} />
			{/if}
			<Select aria-label="State" class="w-full sm:w-auto" value={param('state')} onchange={(e) => setParams({ state: e.currentTarget.value })} options={[{ value: '', label: 'Any state' }, { value: 'up', label: 'Up' }, { value: 'down', label: 'Down' }, { value: 'unknown', label: 'Unknown' }]} />
			<Select aria-label="Kind" class="w-full sm:w-auto" value={param('kind')} onchange={(e) => setParams({ kind: e.currentTarget.value })} options={[{ value: '', label: 'Any kind' }, ...monitorKinds.map((k) => ({ value: k.value, label: k.label }))]} />
		{/snippet}
		{#snippet empty()}
			{#if param('q') || param('site') || param('state') || param('kind')}
				<EmptyState title="No monitors match" description="Try other filters.">
					{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, site: null, state: null, kind: null }); }}>Clear filters</Button>{/snippet}
				</EmptyState>
			{:else}
				<EmptyState icon={Activity} title="No uptime monitors yet" description="Watch a client's website, VPN endpoint, mail server or line of business app from an agent on their network.">
					{#snippet action()}{#if can('technician')}<Button size="sm" variant="primary" icon={Plus} onclick={() => (adding = true)}>Add monitor</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</DataTable>
{/if}

{#if adding}
	<MonitorDrawer siteId={sites[0]?.id ?? ''} onclose={() => (adding = false)} ondone={(id) => { adding = false; if (id) goto(`/uptime/${id}`); else monitors.reload(); }} />
{/if}
