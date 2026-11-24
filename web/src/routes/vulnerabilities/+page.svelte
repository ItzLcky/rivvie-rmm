<script lang="ts">
	import { Search, ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime, num } from '#lib/format.js';
	import { paged } from '#lib/paged.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient, withClient } from '#lib/scope.svelte.js';
	import { ROOT_SET } from '#lib/policy/policy.js';
	import { allowed } from '#lib/session.svelte.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
	import { epssPct, type VulnRow, type VulnSummary } from '#lib/vulns.js';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Stat from '#lib/ui/Stat.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import VulnSeverity from '#lib/components/vulns/VulnSeverity.svelte';
	import ByDevice from './ByDevice.svelte';
	import BySoftware from './BySoftware.svelte';
	import Feeds from './Feeds.svelte';
	import NotAssessed from './NotAssessed.svelte';

	const tab = $derived(param('tab', 'cves'));
	const scoped = $derived(currentClient());
	const summary = resource(() => api.get<VulnSummary>(`/vulnerabilities/summary${qs({ client_id: clientId() })}`));

	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null, after: null, before: null }), 250);
		return () => clearTimeout(t);
	});
	const sort = sortState('severity');
	const rows = paged<VulnRow>(() =>
		tab === 'cves'
			? `/vulnerabilities${qs({ client_id: clientId(), severity: param('severity'), kev: param('kev') || undefined, fix: param('fix') || undefined, q: param('q'), sort: sort.key, dir: sort.dir })}`
			: '/vulnerabilities?limit=1'
	);
	const filtered = $derived(!!(param('q') || param('severity') || param('kev') || param('fix')));
</script>

<svelte:head><title>Vulnerabilities</title></svelte:head>

<PageHeader title="Vulnerabilities" description={scoped ? `Known vulnerabilities in the software on ${scoped.name}'s devices.` : 'Known vulnerabilities in installed software: distribution advisories for Linux packages, NVD for mapped Windows applications, with CISA KEV and EPSS.'}>
	{#snippet actions()}<Button icon={ShieldCheck} href="/policies/sets/{ROOT_SET}?section=alerts&item=new&kind=vulnerability">Alert on vulnerabilities</Button>{/snippet}
</PageHeader>

{#if summary.data}
	{@const s = summary.data}
	<section aria-label="Vulnerability totals" class="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
		<Stat label="Critical findings" value={s.critical} tone="danger" href={withClient('/vulnerabilities?severity=critical')} />
		<Stat label="High findings" value={s.high} tone="warning" href={withClient('/vulnerabilities?severity=high')} />
		<Stat label="Known exploited" value={s.kev} tone="danger" href={withClient('/vulnerabilities?kev=true')} />
		<Stat label="Devices affected" value={s.devices_affected} of={s.assessed} href={withClient('/vulnerabilities?tab=devices')} />
		<Stat label="Not assessed" value={s.unassessed} tone="warning" href={withClient('/vulnerabilities?tab=unassessed')} />
	</section>
{/if}

<Tabs
	label="Vulnerability views"
	class="mb-3"
	value={tab}
	onchange={(v) => setParams({ tab: v === 'cves' ? null : v, q: null, severity: null, kev: null, fix: null, after: null, before: null, sort: null, dir: null }, { push: true })}
	items={[
		{ value: 'cves', label: 'By CVE' },
		{ value: 'devices', label: 'By device' },
		{ value: 'software', label: 'By software' },
		{ value: 'unassessed', label: 'Not assessed' },
		...(allowed('security.manage') ? [{ value: 'feeds', label: 'Feeds & products' }] : [])
	]}
/>

{#if tab === 'cves'}
	{#if rows.error && !rows.data}
		<div class="card"><ErrorState error={rows.error} onretry={() => rows.reload()} /></div>
	{:else}
		{#snippet cveCell(r: VulnRow)}
			<a class="hover:text-accent font-mono text-[13px] font-medium whitespace-nowrap" href="/vulnerabilities/{encodeURIComponent(r.key)}">{r.key}</a>
			<div class="text-muted max-w-[28rem] truncate text-xs" title={r.summary}>{r.summary}</div>
		{/snippet}
		{#snippet sevCell(r: VulnRow)}<VulnSeverity severity={r.severity} cvss={r.cvss} kev={r.kev} />{/snippet}
		{#snippet epssCell(r: VulnRow)}<span class="tabular" title="Probability of exploitation in the next 30 days">{epssPct(r.epss)}</span>{/snippet}
		{#snippet pkgCell(r: VulnRow)}<span class="block max-w-56 truncate" title={r.packages.join(', ')}>{r.packages.join(', ')}</span>{/snippet}
		{#snippet devCell(r: VulnRow)}
			<span class="font-semibold tabular">{num(r.devices)}</span>
			{#if r.accepted_devices}<div class="text-muted text-xs">{num(r.accepted_devices)} accepted</div>{/if}
		{/snippet}
		{#snippet fixCell(r: VulnRow)}<span class={r.fix_available ? '' : 'text-muted'}>{r.fix_available ? 'Available' : 'Not yet'}</span>{/snippet}
		{#snippet seenCell(r: VulnRow)}<span class="text-muted whitespace-nowrap" title={datetime(r.first_seen)}>{ago(r.first_seen)}</span>{/snippet}
		<DataTable
			id="vulns"
			caption="Vulnerabilities by CVE"
			activeFilters={[param('severity'), param('kev'), param('fix')].filter(Boolean).length}
			rows={rows.rows}
			key={(r) => r.key}
			loading={rows.loading && !rows.data}
			busy={rows.busy}
			{sort}
			rowHref={(r) => `/vulnerabilities/${encodeURIComponent(r.key)}`}
			columns={[
				{ id: 'cve', label: 'Vulnerability', sort: 'cve', cell: cveCell, hideable: false },
				{ id: 'severity', label: 'Severity', sort: 'severity', cell: sevCell },
				{ id: 'epss', label: 'EPSS', sort: 'epss', cell: epssCell, from: 'md', align: 'right' },
				{ id: 'packages', label: 'Packages', cell: pkgCell, from: 'lg' },
				{ id: 'fix', label: 'Fix', cell: fixCell, from: 'sm' },
				{ id: 'devices', label: 'Devices', sort: 'devices', cell: devCell, align: 'right' },
				{ id: 'seen', label: 'First found', sort: 'first_seen', cell: seenCell, from: 'xl' }
			] satisfies Column<VulnRow>[]}
		>
			{#snippet toolbar()}
				<Input icon={Search} data-search placeholder="CVE, package or summary…" aria-label="Search vulnerabilities" class="min-w-0 flex-1 sm:w-72 sm:flex-none" bind:value={q} />
			{/snippet}
			{#snippet filters()}
				<Select aria-label="Severity" class="w-full sm:w-auto" value={param('severity')} onchange={(e) => setParams({ severity: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Any severity' }, { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'critical,high', label: 'Critical or high' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }, { value: 'unknown', label: 'Unrated' }]} />
				<Select aria-label="Exploited" class="w-full sm:w-auto" value={param('kev')} onchange={(e) => setParams({ kev: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'Exploited or not' }, { value: 'true', label: 'Known exploited (KEV)' }]} />
				<Select aria-label="Fix" class="w-full sm:w-auto" value={param('fix')} onchange={(e) => setParams({ fix: e.currentTarget.value, after: null, before: null })} options={[{ value: '', label: 'With or without a fix' }, { value: 'true', label: 'Fix available' }, { value: 'false', label: 'No fix yet' }]} />
			{/snippet}
			{#snippet empty()}
				{#if filtered}
					<EmptyState title="No vulnerabilities match" description="Try other filters.">
						{#snippet action()}<Button size="sm" onclick={() => { q = ''; setParams({ q: null, severity: null, kev: null, fix: null }); }}>Clear filters</Button>{/snippet}
					</EmptyState>
				{:else}
					<EmptyState icon={ShieldCheck} title="No known vulnerabilities" description={summary.data?.last_sync_at ? `Advisories last synced ${ago(summary.data.last_sync_at)}.` : 'The advisory feeds haven’t synced yet: they sync daily for the operating systems in the fleet, or sync them now under Feeds & products.'} />
				{/if}
			{/snippet}
			{#snippet footer()}
				{#if rows.data && (rows.data.next || rows.data.prev)}
					<Pagination shown={rows.rows.length} total={rows.data.total} hasPrev={!!rows.data.prev} hasNext={!!rows.data.next} pageSize={rows.pageSize} onprev={rows.prev} onnext={rows.next} onfirst={rows.first} onpagesize={rows.setPageSize} />
				{/if}
			{/snippet}
		</DataTable>
	{/if}
{:else if tab === 'devices'}
	<ByDevice />
{:else if tab === 'software'}
	<BySoftware />
{:else if tab === 'unassessed'}
	<NotAssessed />
{:else if tab === 'feeds'}
	<Feeds />
{/if}
