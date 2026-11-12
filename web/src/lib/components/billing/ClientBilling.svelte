<script lang="ts">
	import { FileSignature, Lock, Plus, ReceiptText } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { billingSettings, clientCurrency, currencies, forgetClientCurrency } from '#lib/billing/currency.js';
	import { contractState, day, invoiceTitle } from '#lib/billing/meta.js';
	import { formatMoney } from '#lib/billing/money.js';
	import type { ClientBilling, Contract, Invoice } from '#lib/billing/types.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import ContractEditor from './ContractEditor.svelte';
	import ContractSummary from './ContractSummary.svelte';
	import InvoiceBadges from './InvoiceBadges.svelte';

	/** The Billing tab of a client: its contracts, recent invoices, and billing details. */
	let { clientId }: { clientId: string } = $props();

	const manage = $derived(allowed('billing.manage'));
	const contracts = resource(() => api.get<Contract[]>(`/contracts?client_id=${clientId}`));
	const invoices = resource(() => api.get<Invoice[]>(`/invoices?client_id=${clientId}`));
	const billing = resource(() => api.get<ClientBilling>(`/clients/${clientId}/billing`));
	let companyCurrency = $state('');
	let currency = $state('');
	$effect(() => {
		billingSettings().then((s) => (companyCurrency = s.currency), () => {});
	});
	$effect(() => {
		const id = clientId;
		void billing.data;
		clientCurrency(id).then((c) => (currency = c), () => {});
	});

	let form = $state({ currency: '', billing_address: '' });
	let formFor = '';
	$effect(() => {
		const b = billing.data;
		if (b && formFor !== clientId) {
			formFor = clientId;
			form = { currency: b.currency ?? '', billing_address: b.billing_address };
		}
	});
	const dirty = $derived(!!billing.data && (form.currency !== (billing.data.currency ?? '') || form.billing_address !== billing.data.billing_address));
	const currencyOptions = $derived([
		{ value: '', label: companyCurrency ? `Company currency (${companyCurrency})` : 'Company currency' },
		...[...new Set([...currencies, ...(form.currency ? [form.currency] : [])])].sort().map((c) => ({ value: c, label: c }))
	]);
	let saving = $state(false);
	async function save(e: SubmitEvent) {
		e.preventDefault();
		saving = true;
		const ok = await attempt(() => api.put(`/clients/${clientId}/billing`, { currency: form.currency || null, billing_address: form.billing_address }), 'Billing details saved.');
		saving = false;
		if (ok) {
			forgetClientCurrency(clientId);
			formFor = '';
			billing.reload();
		}
	}

	let adding = $state(false);
</script>

{#if !allowed('billing.read')}
	<div class="card"><EmptyState icon={Lock} title="No access to billing" description="Ask an admin for the billing permission." /></div>
{:else}
	<div class="grid gap-5 lg:grid-cols-2">
		<section class="card lg:col-span-2" aria-labelledby="cb-contracts-h">
			<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
				<h2 id="cb-contracts-h" class="font-semibold">Contracts</h2>
				{#if manage}<Button size="sm" icon={Plus} onclick={() => (adding = true)}>Add contract</Button>{/if}
			</header>
			<Async res={contracts} compact>
				{#snippet children(list)}
					{#if list.length}
						<ul class="divide-border divide-y">
							{#each list as c (c.id)}
								{@const s = contractState(c)}
								<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-3 text-sm">
									<div class="min-w-0 flex-1">
										<a href="/contracts/{c.id}" class="font-medium hover:underline">{c.name}</a>
										<div class="text-muted text-xs"><ContractSummary contract={c} {currency} /></div>
									</div>
									<span class="text-muted text-xs whitespace-nowrap">{day(c.start_date)} – {c.end_date ? day(c.end_date) : 'open-ended'}</span>
									<Badge tone={s.tone} dot>{s.label}</Badge>
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact icon={FileSignature} title="No contracts" description="Without one, all time is billed at the normal rates." />
					{/if}
				{/snippet}
			</Async>
		</section>

		<section class="card" aria-labelledby="cb-inv-h">
			<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
				<h2 id="cb-inv-h" class="font-semibold">Recent invoices</h2>
				<a href="/billing?client={clientId}" class="text-muted hover:text-fg text-xs hover:underline">All invoices</a>
			</header>
			<Async res={invoices} compact>
				{#snippet children(list)}
					{#if list.length}
						<ul class="divide-border divide-y">
							{#each list.slice(0, 8) as i (i.id)}
								<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-5 py-2.5 text-sm">
									<div class="min-w-0 flex-1">
										<a href="/billing/{i.id}" class="font-medium hover:underline">{invoiceTitle(i)}</a>
										<div class="text-muted text-xs">{day(i.issue_date)}</div>
									</div>
									<InvoiceBadges invoice={i} />
									<span class="w-24 text-right font-medium tabular">{formatMoney(i.total, i.currency)}</span>
								</li>
							{/each}
						</ul>
					{:else}
						<EmptyState compact icon={ReceiptText} title="No invoices yet" />
					{/if}
				{/snippet}
			</Async>
		</section>

		<section class="card" aria-labelledby="cb-details-h">
			<header class="border-border border-b px-5 py-3">
				<h2 id="cb-details-h" class="font-semibold">Billing details</h2>
			</header>
			<Async res={billing} compact>
				{#snippet children(_b)}
					<form class="space-y-3 p-5" onsubmit={save}>
						<Field label="Currency" id="cb-currency" hint="Drafts follow a change; finalised invoices keep theirs.">
							<Select id="cb-currency" class="w-full" bind:value={form.currency} options={currencyOptions} disabled={!manage} />
						</Field>
						<Field label="Billing address" id="cb-address" hint="Printed under the client’s name on invoices.">
							<Textarea id="cb-address" rows={4} bind:value={form.billing_address} maxlength={1000} disabled={!manage} />
						</Field>
						{#if manage}<div class="flex justify-end"><Button type="submit" variant="primary" loading={saving} disabled={!dirty}>Save</Button></div>{/if}
					</form>
				{/snippet}
			</Async>
		</section>
	</div>

	{#if adding}
		<ContractEditor
			{clientId}
			onclose={() => (adding = false)}
			onsaved={() => {
				adding = false;
				contracts.reload();
			}}
		/>
	{/if}
{/if}
