<script lang="ts">
	import { BellOff, Plus, Search, ShieldCheck } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { datetime, osLabels } from '#lib/format.js';
	import MuteDialog from '#lib/components/MuteDialog.svelte';
	import { describeMute, describePolicy, kindLabels } from '#lib/monitoring/labels.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, currentClient, withClient } from '#lib/scope.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Mute, Policy } from '#lib/types.js';
	import { param, qs, setParams, sortState } from '#lib/url.svelte.js';
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

	const mutes = resource(() => api.get<Mute[]>(`/alert-mutes${qs({ client_id: clientId() })}`));
	let addingMute = $state(false);
	async function removeMute(m: Mute) {
		if (await attempt(() => api.del(`/alert-mutes/${m.id}`), m.ends_at ? 'Snooze ended.' : 'Maintenance window removed.')) mutes.reload();
	}

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

<section class="card mt-6" aria-labelledby="mutes-title">
	<header class="border-border flex min-h-12 flex-wrap items-center gap-2 border-b px-4 py-2">
		<div class="min-w-0 flex-1">
			<h2 id="mutes-title" class="panel-title">Maintenance windows</h2>
			<p class="text-muted text-xs">Alerts that open during these are kept, but nobody is notified and no ticket opens. Snoozes for one agent are set on the agent.</p>
		</div>
		{#if can('technician') && clients.list.length}<Button size="sm" icon={BellOff} onclick={() => (addingMute = true)}>Add window</Button>{/if}
	</header>
	{#if mutes.data?.length}
		<ul class="divide-border divide-y">
			{#each mutes.data as m (m.id)}
				<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
					<div class="min-w-0 flex-1">
						<div class="flex flex-wrap items-center gap-2">
							{#if m.agent_id}<a class="hover:text-accent font-medium" href="/agents/{m.agent_id}?tab=alerts">{m.target_name}</a>{:else}<span class="font-medium">{m.target_name}</span>{/if}
							<span class="text-muted">{describeMute(m, datetime)}</span>
							{#if m.active}<Badge tone="warning">Now</Badge>{/if}
						</div>
						{#if m.reason || m.created_by_name}<div class="text-muted text-xs">{[m.reason, m.created_by_name].filter(Boolean).join(' · ')}</div>{/if}
					</div>
					{#if can('technician')}<Button size="sm" variant="ghost" onclick={() => removeMute(m)}>{m.ends_at ? 'End' : 'Remove'}</Button>{/if}
				</li>
			{/each}
		</ul>
	{:else if !mutes.loading}
		<EmptyState compact title="No maintenance windows" description="Add one for regular work (nightly backups, weekend patching) so planned reboots don't page anyone." />
	{/if}
</section>

{#if addingMute}<MuteDialog onclose={() => (addingMute = false)} onsaved={() => mutes.reload()} />{/if}
