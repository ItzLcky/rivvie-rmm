<script lang="ts">
	import { FileSignature, Lock, Plus } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { clientCurrencies } from '#lib/billing/currency.js';
	import { contractState, cycleLabel, day } from '#lib/billing/meta.js';
	import type { Contract } from '#lib/billing/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, currentClient } from '#lib/scope.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import ContractEditor from '#lib/components/billing/ContractEditor.svelte';
	import ContractSummary from '#lib/components/billing/ContractSummary.svelte';

	const manage = $derived(allowed('billing.manage'));
	const scoped = $derived(currentClient());
	const list = resource(() => api.get<Contract[]>(`/contracts${qs({ client_id: clientId() })}`));
	let currency = $state<Record<string, string>>({});
	$effect(() => {
		const ids = (list.data ?? []).map((c) => c.client_id).filter((id) => !(id in currency));
		if (ids.length) clientCurrencies(ids).then((m) => (currency = { ...currency, ...m }));
	});

	const views = [
		{ value: 'active', label: 'Active' },
		{ value: 'upcoming', label: 'Not started' },
		{ value: 'ended', label: 'Ended' },
		{ value: 'all', label: 'All' }
	];
	const view = $derived(views.some((v) => v.value === param('view')) ? param('view') : 'active');
	const rows = $derived(
		(list.data ?? []).filter((c) => {
			if (view === 'all') return true;
			const s = contractState(c).label;
			return view === 'active' ? s === 'Active' : view === 'ended' ? s === 'Ended' : s === 'Not started';
		})
	);
	const counts = $derived.by(() => {
		const n = { active: 0, upcoming: 0, ended: 0 };
		for (const c of list.data ?? []) {
			const s = contractState(c).label;
			if (s === 'Active') n.active++;
			else if (s === 'Ended') n.ended++;
			else n.upcoming++;
		}
		return n;
	});

	let adding = $state(false);
</script>

<svelte:head><title>Contracts</title></svelte:head>

{#if !allowed('billing.read')}
	<PageHeader title="Contracts" />
	<div class="card"><EmptyState icon={Lock} title="No access to billing" description="Ask an admin for the billing permission to see contracts." /></div>
{:else}
	<PageHeader title="Contracts" count={list.data?.length ?? null} description={scoped ? `${scoped.name}'s agreements.` : 'What each client pays for every cycle: managed devices or users, blocks of hours, and recurring services.'}>
		{#snippet actions()}{#if manage}<Button variant="primary" icon={Plus} onclick={() => (adding = true)}>Add contract</Button>{/if}{/snippet}
	</PageHeader>

	<Tabs
		label="Contract state"
		class="mb-3"
		value={view}
		onchange={(v) => setParams({ view: v === 'active' ? null : v })}
		items={views.map((v) => ({ ...v, count: v.value === 'all' ? undefined : counts[v.value as keyof typeof counts] || undefined }))}
	/>

	{#if list.error && !list.data}
		<div class="card"><ErrorState error={list.error} onretry={() => list.reload()} /></div>
	{:else}
		{#snippet nameCell(c: Contract)}
			<a href="/contracts/{c.id}" class="font-medium hover:underline">{c.name}</a>
			{#if !scoped}<div class="text-muted text-xs">{c.client_name}</div>{/if}
		{/snippet}
		{#snippet kindCell(c: Contract)}<ContractSummary contract={c} currency={currency[c.client_id] ?? ''} />{/snippet}
		{#snippet periodCell(c: Contract)}<span class="whitespace-nowrap">{day(c.start_date)} – {c.end_date ? day(c.end_date) : 'open-ended'}</span>{/snippet}
		{#snippet cycleCell(c: Contract)}{cycleLabel(c.billing_cycle)}{/snippet}
		{#snippet slaCell(c: Contract)}<span class="text-muted">{c.sla_policy_name ?? '–'}</span>{/snippet}
		{#snippet stateCell(c: Contract)}
			{@const s = contractState(c)}
			<Badge tone={s.tone} dot>{s.label}</Badge>
		{/snippet}

		<DataTable
			id="contracts"
			caption="Contracts"
			{rows}
			key={(c) => c.id}
			loading={list.loading}
			busy={list.busy}
			rowHref={(c) => `/contracts/${c.id}`}
			columns={[
				{ id: 'name', label: 'Contract', cell: nameCell, hideable: false },
				{ id: 'kind', label: 'Type and price', cell: kindCell, hideable: false },
				{ id: 'period', label: 'Term', cell: periodCell, from: 'md' },
				{ id: 'cycle', label: 'Cycle', cell: cycleCell, from: 'lg' },
				{ id: 'sla', label: 'SLA', cell: slaCell, from: 'xl', defaultHidden: true },
				{ id: 'state', label: 'State', cell: stateCell, from: 'sm' }
			] satisfies Column<Contract>[]}
		>
			{#snippet empty()}
				{#if list.data?.length}
					<EmptyState compact title="No contracts here" />
				{:else}
					<EmptyState icon={FileSignature} title="No contracts yet" description="Add one per agreement; invoice runs bill each cycle and apply its rates and coverage to time.">
						{#snippet action()}{#if manage}<Button variant="primary" icon={Plus} onclick={() => (adding = true)}>Add contract</Button>{/if}{/snippet}
					</EmptyState>
				{/if}
			{/snippet}
		</DataTable>
	{/if}
{/if}

{#if adding}
	<ContractEditor
		clientId={clientId() || undefined}
		onclose={() => (adding = false)}
		onsaved={() => {
			adding = false;
			list.reload();
		}}
	/>
{/if}
