<script lang="ts">
	import { Plus, Search, ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { osLabels } from '#lib/format.js';
	import { describePolicy, kindLabels } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { Policy } from '#lib/types.js';
	import { param, setParams, sortState } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import SeverityBadge from '#lib/components/SeverityBadge.svelte';

	const res = resource(() => api.get<Policy[]>('/alert-policies'));
	const sort = sortState('name');
	let q = $state(param('q'));
	$effect(() => {
		const v = q;
		const t = setTimeout(() => setParams({ q: v.trim() || null }), 250);
		return () => clearTimeout(t);
	});
	const kind = $derived(param('kind'));
	const scoped = $derived(currentClient());
	const rank = { critical: 0, warning: 1, info: 2 };
	const keyed: Record<string, (p: Policy) => string | number> = {
		name: (p) => p.name.toLowerCase(),
		kind: (p) => kindLabels[p.kind],
		severity: (p) => rank[p.severity],
		scope: (p) => `${p.client_name ?? ''} ${p.site_name ?? ''}`.toLowerCase(),
		open: (p) => p.open_alerts
	};
	const rows = $derived.by(() => {
		const f = param('q').toLowerCase();
		const cid = clientId();
		const list = (res.data ?? []).filter(
			(p) => (!f || `${p.name} ${describePolicy(p)}`.toLowerCase().includes(f)) && (!kind || p.kind === kind) && (!cid || !p.client_id || p.client_id === cid)
		);
		const k = keyed[sort.key] ?? keyed.name;
		const sign = sort.dir === 'asc' ? 1 : -1;
		return [...list].sort((a, b) => (k(a) < k(b) ? -sign : k(a) > k(b) ? sign : 0));
	});
	const mayEdit = (p: Policy) => (p.client_id ? can('technician') : can('admin'));
	const canCreate = $derived(can('admin') || (can('technician') && clients.list.length > 0));

	async function toggle(p: Policy, enabled: boolean) {
		const body = { ...p, enabled };
		res.update((list) => list.map((x) => (x.id === p.id ? { ...x, enabled } : x)));
		try {
			await api.put(`/alert-policies/${p.id}`, body);
			toast.success(`${p.name} ${enabled ? 'enabled' : 'disabled'}.`);
		} catch (e) {
			toast.error(e);
			res.reload();
		}
	}
</script>

<PageHeader title="Alert policies" count={res.data ? rows.length : null} description={scoped ? `MSP-wide policies, plus policies for ${scoped.name} only.` : 'What raises an alert, on which agents, and who hears about it.'}>
	{#snippet actions()}
		{#if canCreate}<Button variant="primary" icon={Plus} href={withClient('/policies/new')}>New policy</Button>{/if}
	{/snippet}
</PageHeader>

{#if res.error && !res.data}
	<div class="card"><ErrorState error={res.error} onretry={() => res.reload()} /></div>
{:else}
	{#snippet nameCell(p: Policy)}
		<a class="hover:text-accent font-medium" href="/policies/{p.id}">{p.name}</a>
		<div class="text-muted max-w-md truncate text-xs">{describePolicy(p)}</div>
	{/snippet}
	{#snippet kindCell(p: Policy)}{kindLabels[p.kind]}{/snippet}
	{#snippet sevCell(p: Policy)}<SeverityBadge severity={p.severity} />{/snippet}
	{#snippet scopeCell(p: Policy)}
		{#if p.client_name}<Badge>{p.client_name}{p.site_name ? ` › ${p.site_name}` : ''}</Badge>{:else}<Badge tone="accent">All clients</Badge>{/if}
		{#if p.os_family}<span class="text-muted ml-1 text-xs">{osLabels[p.os_family]} only</span>{/if}
	{/snippet}
	{#snippet notifyCell(p: Policy)}<span class="text-muted">{p.channel_ids.length ? `${p.channel_ids.length} channel${p.channel_ids.length === 1 ? '' : 's'}` : 'None'}</span>{/snippet}
	{#snippet openCell(p: Policy)}
		{#if p.open_alerts}<a class="text-danger font-medium hover:underline" href="/alerts?policy={p.id}">{p.open_alerts}</a>{:else}<span class="text-muted" aria-label="none">–</span>{/if}
	{/snippet}
	{#snippet enabledCell(p: Policy)}
		<Switch checked={p.enabled} disabled={!mayEdit(p)} label="{p.enabled ? 'Disable' : 'Enable'} {p.name}" onchange={(c) => toggle(p, c)} />
	{/snippet}

	<DataTable
		id="policies"
		caption="Alert policies"
		{rows}
		key={(p) => p.id}
		loading={res.loading}
		{sort}
		rowHref={(p) => `/policies/${p.id}`}
		columns={[
			{ id: 'name', label: 'Policy', sort: 'name', cell: nameCell, hideable: false },
			{ id: 'kind', label: 'Type', sort: 'kind', cell: kindCell, from: 'md' },
			{ id: 'severity', label: 'Severity', sort: 'severity', cell: sevCell, from: 'sm' },
			{ id: 'scope', label: 'Applies to', sort: 'scope', cell: scopeCell, from: 'lg' },
			{ id: 'notify', label: 'Notifies', cell: notifyCell, from: 'xl' },
			{ id: 'open', label: 'Open', sort: 'open', cell: openCell, align: 'right' },
			{ id: 'enabled', label: 'On', cell: enabledCell, hideable: false, class: 'w-16' }
		] satisfies Column<Policy>[]}
	>
		{#snippet toolbar()}
			<Input icon={Search} data-search placeholder="Name or rule…" aria-label="Search policies" class="w-full sm:w-64" bind:value={q} />
			<Select aria-label="Type" class="w-auto" value={kind} onchange={(e) => setParams({ kind: e.currentTarget.value })} options={[{ value: '', label: 'Any type' }, ...Object.entries(kindLabels).map(([value, label]) => ({ value, label }))]} />
		{/snippet}
		{#snippet empty()}
			{#if param('q') || kind}
				<EmptyState compact title="No policies match" />
			{:else}
				<EmptyState icon={ShieldCheck} title="No alert policies yet" description="A policy watches agents for one problem (offline, high CPU, a stopped service, a failed script...) and opens an alert when it happens.">
					{#snippet action()}{#if canCreate}<Button variant="primary" icon={Plus} href={withClient('/policies/new')}>New policy</Button>{/if}{/snippet}
				</EmptyState>
			{/if}
		{/snippet}
	</DataTable>
{/if}
