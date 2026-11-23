<script lang="ts">
	import { Plus, RefreshCw, Search } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, num, plural } from '#lib/format.js';
	import { liveReload } from '#lib/live.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, loadClients } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { opLabels, providerLabels, runLabel, runTone, sourcesOf, type SoftwarePackage, type SoftwareRun, type SoftwareUpdates } from '#lib/software.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import PackageForm from '#lib/components/software/PackageForm.svelte';
	import SoftwareUpdatesTable from '#lib/components/software/UpdatesTable.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import { goto } from '$app/navigation';

	const tab = $derived(param('tab', 'catalog'));
	$effect(() => {
		loadClients();
	});

	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});

	const catalog = resource(() => api.get<SoftwarePackage[]>(`/software/packages${qs({ client_id: clientId(), q: param('q'), platform: param('platform') })}`));
	const updates = resource(() => api.get<SoftwareUpdates>(`/software/updates${qs({ client_id: clientId(), q: tab === 'updates' ? param('q') : null })}`));
	const runs = resource(() => (tab === 'runs' ? api.get<SoftwareRun[]>(`/software/runs${qs({ client_id: clientId(), status: param('status') || null, limit: 200 })}`) : Promise.resolve(null)));
	liveReload(
		() => {
			catalog.reload();
			updates.reload();
			if (tab === 'runs') runs.reload();
		},
		(e) => e.type === 'software',
		{ debounceMs: 2000, pollMs: 60000 }
	);
	let adding = $state(false);

	async function scanAll() {
		const ids = [...new Set((updates.data?.items ?? []).map((d) => d.agent_id))];
		if (!ids.length) return;
		await attempt(() => api.post('/software/scan', { agent_ids: ids }), 'Asked those devices to rescan.');
	}
</script>

<svelte:head><title>Software</title></svelte:head>

<PageHeader title="Software" description="A catalog of packages to deploy with winget, Chocolatey, apt, dnf or an uploaded installer, kept as desired state in policy sets.">
	{#snippet actions()}
		{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (adding = true)}>New package</Button>{/if}
	{/snippet}
</PageHeader>

<Tabs
	label="Software sections"
	class="mb-3"
	value={tab}
	onchange={(v) => setParams({ tab: v === 'catalog' ? null : v, status: null }, { push: true })}
	items={[
		{ value: 'catalog', label: 'Catalog', count: catalog.data ? num(catalog.data.length) : undefined },
		{ value: 'updates', label: 'Updates', count: updates.data?.items.length ? num(updates.data.items.length) : undefined },
		{ value: 'runs', label: 'History' }
	]}
/>

{#if tab === 'catalog'}
	{#snippet nameCell(p: SoftwarePackage)}
		<a class="hover:text-accent font-medium" href="/software/{p.id}">{p.name}</a>
		<div class="text-muted max-w-md truncate text-xs">{[p.publisher, p.version ? `pinned to ${p.version}` : 'latest'].filter(Boolean).join(' · ')}</div>
	{/snippet}
	{#snippet viaCell(p: SoftwarePackage)}
		{#if sourcesOf(p).length}
			<span class="flex flex-wrap gap-1">{#each sourcesOf(p) as s (s)}<Badge>{s}</Badge>{/each}</span>
		{:else}
			<Badge tone="warning" title="Upload an installer or add a package id before it can be deployed">No source yet</Badge>
		{/if}
	{/snippet}
	{#snippet scopeCell(p: SoftwarePackage)}{#if p.client_name}<Badge>{p.client_name}</Badge>{:else}<span class="text-muted">Every client</span>{/if}{/snippet}
	{#snippet installedCell(p: SoftwarePackage)}<span class="tabular">{num(p.installed_on)}</span>{/snippet}
	{#snippet updatesCell(p: SoftwarePackage)}{#if p.updates}<a class="text-warning font-medium hover:underline" href="/software?tab=updates&q={encodeURIComponent(p.name)}">{num(p.updates)}</a>{:else}<span class="text-muted" aria-label="none">–</span>{/if}{/snippet}
	{#snippet policiesCell(p: SoftwarePackage)}<span class="text-muted tabular">{p.policies || '–'}</span>{/snippet}
	{#if catalog.error && !catalog.data}
		<div class="card"><ErrorState error={catalog.error} onretry={() => catalog.reload()} /></div>
	{:else}
		<DataTable
			id="software-catalog"
			caption="Software catalog"
			rows={catalog.data ?? []}
			key={(p) => p.id}
			loading={catalog.loading}
			busy={catalog.busy}
			rowHref={(p) => `/software/${p.id}`}
			columns={[
				{ id: 'name', label: 'Package', cell: nameCell, hideable: false },
				{ id: 'via', label: 'Deployed with', cell: viaCell, from: 'sm' },
				{ id: 'scope', label: 'Available to', cell: scopeCell, from: 'lg' },
				{ id: 'installed', label: 'Installed on', cell: installedCell, align: 'right' },
				{ id: 'updates', label: 'Updates', cell: updatesCell, align: 'right', from: 'md' },
				{ id: 'policies', label: 'Policies', cell: policiesCell, align: 'right', from: 'xl' }
			] satisfies Column<SoftwarePackage>[]}
		>
			{#snippet toolbar()}
				<Input icon={Search} data-search placeholder="Name, publisher or package id…" aria-label="Search the catalog" class="min-w-0 flex-1 sm:w-72 sm:flex-none" bind:value={q} />
				<Segmented label="Platform" value={param('platform') || 'all'} onchange={(v) => setParams({ platform: v === 'all' ? null : v })} options={[{ value: 'all', label: 'All' }, { value: 'windows', label: 'Windows' }, { value: 'linux', label: 'Linux' }]} />
			{/snippet}
			{#snippet empty()}
				<EmptyState compact title={param('q') ? 'No packages match' : 'The catalog is empty'} description={param('q') ? undefined : 'Add the software you deploy: a winget or Chocolatey id, an apt or dnf package, or an MSI or EXE you upload. Then require it in a policy set, or install it on chosen devices.'} />
			{/snippet}
		</DataTable>
	{/if}
{:else if tab === 'updates'}
	<SoftwareUpdatesTable res={updates} {q} onsearch={(v) => (q = v)} onrescan={scanAll} />
{:else}
	{#snippet whenCell(r: SoftwareRun)}<a class="hover:text-accent whitespace-nowrap" href="/software/runs/{r.id}" title={r.created_at}>{ago(r.created_at)}</a>{/snippet}
	{#snippet whatCell(r: SoftwareRun)}
		<span class="font-medium">{opLabels[r.op]}</span> {r.package_name}
		<div class="text-muted text-xs">{[r.from_version && r.to_version && r.from_version !== r.to_version ? `${r.from_version} → ${r.to_version}` : (r.to_version ?? r.from_version), r.provider ? (providerLabels[r.provider] ?? r.provider) : null].filter(Boolean).join(' · ')}</div>
	{/snippet}
	{#snippet whereCell(r: SoftwareRun)}<a class="hover:text-accent" href="/agents/{r.agent_id}?tab=deployments">{r.hostname}</a><div class="text-muted text-xs">{r.client_name}</div>{/snippet}
	{#snippet statusCell(r: SoftwareRun)}
		<Badge tone={runTone[r.status]}>{runLabel[r.status]}</Badge>
		{#if r.error}<div class="text-danger mt-0.5 max-w-xs truncate text-xs" title={r.error}>{r.error}</div>{/if}
	{/snippet}
	{#snippet byCell(r: SoftwareRun)}<span class="text-muted">{r.trigger === 'policy' ? 'Policy' : (r.created_by_name ?? 'Manual')}</span>{/snippet}
	<DataTable
		id="software-runs"
		caption="Software installs, upgrades and removals"
		rows={runs.data ?? []}
		key={(r) => r.id}
		loading={runs.loading}
		busy={runs.busy}
		rowHref={(r) => `/software/runs/${r.id}`}
		columns={[
			{ id: 'when', label: 'When', cell: whenCell, hideable: false },
			{ id: 'what', label: 'What', cell: whatCell, hideable: false },
			{ id: 'where', label: 'Device', cell: whereCell },
			{ id: 'status', label: 'Result', cell: statusCell },
			{ id: 'by', label: 'Started by', cell: byCell, from: 'lg' }
		] satisfies Column<SoftwareRun>[]}
	>
		{#snippet toolbar()}
			<Segmented label="Result" value={param('status') || 'all'} onchange={(v) => setParams({ status: v === 'all' ? null : v })} options={[{ value: 'all', label: 'All' }, { value: 'failed,lost', label: 'Failed' }, { value: 'queued,sent', label: 'In progress' }]} />
			<Button size="sm" variant="ghost" icon={RefreshCw} onclick={() => runs.reload()}>Refresh</Button>
		{/snippet}
		{#snippet empty()}<EmptyState compact title="No runs yet" description="Installs, upgrades and removals appear here, from policies and from people." />{/snippet}
	</DataTable>
{/if}

{#if adding}
	<Modal title="New package" description="Add a package to the catalog." size="lg" onclose={() => (adding = false)}>
		<PackageForm ondone={(p) => goto(`/software/${p.id}`)} oncancel={() => (adding = false)} />
	</Modal>
{/if}
