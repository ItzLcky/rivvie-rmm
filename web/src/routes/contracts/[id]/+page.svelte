<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Landmark, Lock, Pencil, SlidersHorizontal, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { clientCurrency } from '#lib/billing/currency.js';
	import { balanceTone, contractState, cycleLabel, day, deviceFilters, kindLabel, perCycle } from '#lib/billing/meta.js';
	import { formatHours, formatMoney, formatQuantity, hoursToMinutes, lineAmount } from '#lib/billing/money.js';
	import type { BankEntry, ContractDetail, UserRates, WorkType } from '#lib/billing/types.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import ContractEditor from '#lib/components/billing/ContractEditor.svelte';

	const id = $derived(page.params.id!);
	const ct = resource(() => api.get<ContractDetail>(`/contracts/${id}`), { keep: false });
	const manage = $derived(allowed('billing.manage'));
	let workTypes = $state<WorkType[]>([]);
	let people = $state<UserRates[]>([]);
	let currency = $state('');
	$effect(() => {
		api.get<WorkType[]>('/work-types').then((w) => (workTypes = w)).catch(() => {});
		api.get<UserRates[]>('/billing/rates').then((p) => (people = p)).catch(() => {});
	});
	$effect(() => {
		const cid = ct.data?.client_id;
		if (cid) clientCurrency(cid).then((c) => (currency = c), toast.error);
	});
	const typeName = (wid: string) => workTypes.find((w) => w.id === wid)?.name ?? 'Unknown work type';
	const money = (v: number | null) => (currency ? formatMoney(v, currency) : '…');

	let editing = $state(false);
	async function remove() {
		const c = ct.data!;
		const ok = await confirmAction({ title: `Delete ${c.name}?`, message: 'Only contracts that were never invoiced can be deleted; otherwise give it an end date.', confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/contracts/${c.id}`), `${c.name} deleted.`))) goto('/contracts', { replace: true });
	}

	// --- bank ------------------------------------------------------------------------------------
	let adjust = $state<{ dir: 'add' | 'remove'; hours: string; note: string } | null>(null);
	let busy = $state(false);
	async function doAdjust(e: SubmitEvent) {
		e.preventDefault();
		const a = adjust!;
		const m = hoursToMinutes(a.hours);
		if (m === null || m <= 0) return toast.error('Enter the hours to add or remove.');
		busy = true;
		const ok = await attempt(() => api.post(`/contracts/${id}/bank`, { minutes: a.dir === 'add' ? m : -m, note: a.note.trim() }), 'Bank adjusted.');
		busy = false;
		if (ok) {
			adjust = null;
			ct.reload();
		}
	}
	const reasons: Record<BankEntry['reason'], string> = { purchase: 'Bought', usage: 'Used', adjustment: 'Adjusted' };
</script>

<svelte:head><title>{ct.data?.name ?? 'Contract'}</title></svelte:head>

{#if !allowed('billing.read')}
	<PageHeader title="Contract" crumbs={[{ label: 'Contracts', href: '/contracts' }]} />
	<div class="card"><EmptyState icon={Lock} title="No access to billing" /></div>
{:else if ct.error}
	<PageHeader title="Contract" crumbs={[{ label: 'Contracts', href: '/contracts' }]} />
	<div class="card"><ErrorState error={ct.error} onretry={() => ct.reload()} /></div>
{:else if !ct.data}
	<div class="space-y-4"><Skeleton class="h-10 w-72" /><Skeleton class="h-48 w-full" /></div>
{:else}
	{@const c = ct.data}
	{@const s = contractState(c)}
	{@const per = perCycle(c.billing_cycle)}
	<PageHeader
		title={c.name}
		crumbs={[{ label: 'Contracts', href: '/contracts' }, { label: c.client_name, href: `/clients/${c.client_id}` }, { label: c.name }]}
		menu={manage ? [{ label: 'Delete contract', icon: Trash2, danger: true, onSelect: remove }] : []}
	>
		{#snippet meta()}<Badge tone={s.tone} dot>{s.label}</Badge>{/snippet}
		{#snippet subtitle()}
			<a href="/clients/{c.client_id}" class="hover:text-fg hover:underline">{c.client_name}</a>
			<span>{kindLabel(c.kind)} · {cycleLabel(c.billing_cycle)}</span>
			<span>{day(c.start_date)} – {c.end_date ? day(c.end_date) : 'open-ended'}</span>
		{/snippet}
		{#snippet actions()}{#if manage}<Button icon={Pencil} onclick={() => (editing = true)}>Edit</Button>{/if}{/snippet}
	</PageHeader>

	<div class="grid gap-5 lg:grid-cols-[1fr_22rem]">
		<div class="min-w-0 space-y-5">
			{#if c.kind === 'block_hours'}
				<section class="card" aria-labelledby="bank-h">
					<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
						<div>
							<h2 id="bank-h" class="font-semibold">Hours bank</h2>
							<p class="text-muted text-xs">Each invoiced cycle adds {formatHours(c.block_minutes)}; approved time on covered work draws it down.</p>
						</div>
						{#if manage}<Button size="sm" icon={SlidersHorizontal} onclick={() => (adjust = { dir: 'add', hours: '', note: '' })}>Adjust bank</Button>{/if}
					</header>
					<div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-5 py-4">
						<span class={['text-3xl font-semibold tabular', balanceTone(c) === 'danger' ? 'text-danger' : balanceTone(c) === 'warning' ? 'text-warning' : '']}>{formatHours(c.balance_minutes ?? 0)}</span>
						<span class="text-muted text-sm">left{#if c.low_balance_minutes} · warns below {formatHours(c.low_balance_minutes)}{/if}</span>
					</div>
					{#if c.bank.length}
						<div class="overflow-x-auto">
							<table class="table">
								<thead><tr><th>When</th><th>What</th><th class="text-right">Hours</th><th>Note</th></tr></thead>
								<tbody>
									{#each c.bank as b (b.id)}
										<tr>
											<td class="text-muted text-xs whitespace-nowrap"><time datetime={b.created_at}>{datetime(b.created_at)}</time></td>
											<td class="whitespace-nowrap">
												{reasons[b.reason]}
												{#if b.ticket_number}<span class="text-muted text-xs"> · ticket #{b.ticket_number}</span>{/if}
												{#if b.invoice_number}<span class="text-muted text-xs"> · {b.invoice_number}</span>{/if}
											</td>
											<td class={['text-right font-medium tabular whitespace-nowrap', b.minutes < 0 ? 'text-danger' : 'text-success']}>{b.minutes > 0 ? '+' : ''}{formatHours(b.minutes)}</td>
											<td class="text-muted text-sm">{b.note}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{:else}
						<EmptyState compact icon={Landmark} title="Nothing in the ledger yet" description="Hours are added when a cycle is invoiced." />
					{/if}
				</section>
			{/if}

			{#if c.kind === 'recurring'}
				<section class="card" aria-labelledby="items-h">
					<header class="border-border border-b px-5 py-3"><h2 id="items-h" class="font-semibold">Billed each {per}</h2></header>
					<div class="overflow-x-auto">
						<table class="table">
							<thead><tr><th>Item</th><th class="text-right">Qty</th><th class="text-right">Unit price</th><th class="text-right">Amount</th></tr></thead>
							<tbody>
								<tr><td>Fee</td><td class="text-right tabular">1</td><td class="text-right tabular">{money(c.unit_price)}</td><td class="text-right tabular">{money(c.unit_price)}</td></tr>
								{#each c.items as it, n (n)}
									<tr>
										<td>{it.description}</td>
										<td class="text-right tabular">{formatQuantity(it.quantity_milli)}</td>
										<td class="text-right tabular">{money(it.unit_price)}</td>
										<td class="text-right tabular">{money(lineAmount(it.quantity_milli, it.unit_price))}</td>
									</tr>
								{/each}
							</tbody>
							<tfoot>
								<tr>
									<th scope="row" colspan="3" class="text-right">Each {per}</th>
									<td class="text-right font-semibold tabular">{money(c.unit_price + c.items.reduce((t, it) => t + lineAmount(it.quantity_milli, it.unit_price), 0))}</td>
								</tr>
							</tfoot>
						</table>
					</div>
				</section>
			{/if}

			<section class="card" aria-labelledby="cov-h">
				<header class="border-border border-b px-5 py-3"><h2 id="cov-h" class="font-semibold">Work and rates</h2></header>
				<div class="space-y-4 px-5 py-4 text-sm">
					{#if c.kind !== 'time_materials'}
						<div>
							<h3 class="label">{c.kind === 'block_hours' ? 'Draws from the bank' : 'Covered at no extra charge'}</h3>
							{#if c.covered_work_type_ids.length}
								<ul class="flex flex-wrap gap-1.5">{#each c.covered_work_type_ids as w (w)}<li><Badge>{typeName(w)}</Badge></li>{/each}</ul>
							{:else}
								<p class="text-muted">Nothing: all time is billable.</p>
							{/if}
						</div>
					{/if}
					<div>
						<h3 class="label">Rate overrides</h3>
						{#if c.rate_overrides.length}
							<dl class="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1">
								{#each c.rate_overrides as o (o.work_type_id)}<dt>{typeName(o.work_type_id)}</dt><dd class="text-right tabular">{money(o.rate)} / h</dd>{/each}
							</dl>
						{:else}
							<p class="text-muted">None: the normal rates apply.</p>
						{/if}
					</div>
				</div>
			</section>

			{#if c.notes}
				<section class="card px-5 py-4" aria-labelledby="notes-h">
					<h2 id="notes-h" class="label">Notes</h2>
					<p class="text-sm whitespace-pre-wrap">{c.notes}</p>
				</section>
			{/if}
		</div>

		<aside>
			<section class="card px-5 py-4" aria-labelledby="terms-h">
				<h2 id="terms-h" class="label">Terms</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
					<dt class="text-muted">Type</dt>
					<dd>{kindLabel(c.kind)}</dd>
					{#if c.kind === 'per_device'}
						<dt class="text-muted">Price</dt><dd>{money(c.unit_price)} per device a {per}</dd>
						<dt class="text-muted">Devices</dt><dd>{deviceFilters.find((d) => d.value === c.device_filter)?.label} · {c.devices} enrolled now</dd>
					{:else if c.kind === 'per_user'}
						<dt class="text-muted">Price</dt><dd>{money(c.unit_price)} per user a {per}</dd>
						<dt class="text-muted">Users</dt><dd>{c.user_count}</dd>
					{:else if c.kind === 'block_hours'}
						<dt class="text-muted">Price</dt><dd>{money(c.unit_price)} a {per}</dd>
						<dt class="text-muted">Hours</dt><dd>{formatHours(c.block_minutes)} a {per}</dd>
						<dt class="text-muted">Overage</dt><dd>{c.overage_rate === null ? 'Normal rates' : `${money(c.overage_rate)} / h`}</dd>
						<dt class="text-muted">Manager</dt><dd>{people.find((p) => p.id === c.manager_id)?.name ?? (c.manager_id ? '…' : 'Nobody')}</dd>
					{:else if c.kind === 'recurring'}
						<dt class="text-muted">Fee</dt><dd>{money(c.unit_price)} a {per}</dd>
					{/if}
					<dt class="text-muted">Cycle</dt>
					<dd>{cycleLabel(c.billing_cycle)}</dd>
					<dt class="text-muted">Starts</dt>
					<dd>{day(c.start_date)}</dd>
					<dt class="text-muted">Ends</dt>
					<dd>{c.end_date ? day(c.end_date) : 'Open-ended'}</dd>
					<dt class="text-muted">SLA</dt>
					<dd>{c.sla_policy_name ?? 'The client’s policy'}</dd>
					{#if currency}<dt class="text-muted">Currency</dt><dd>{currency}</dd>{/if}
				</dl>
			</section>
		</aside>
	</div>

	{#if editing}
		<ContractEditor
			contract={c}
			onclose={() => (editing = false)}
			onsaved={() => {
				editing = false;
				ct.reload();
			}}
		/>
	{/if}

	{#if adjust}
		<Modal title="Adjust the hours bank" description="For hours given back, or a top-up sold outside an invoice run." size="sm" onclose={() => (adjust = null)}>
			<form id="bank-form" class="space-y-3" onsubmit={doAdjust}>
				<Segmented label="Direction" size="md" value={adjust.dir} onchange={(v) => (adjust!.dir = v)} options={[{ value: 'add', label: 'Add hours' }, { value: 'remove', label: 'Remove hours' }]} />
				<Field label="Hours" id="bank-hours" required><Input id="bank-hours" inputmode="decimal" bind:value={adjust.hours} required placeholder="1.5" /></Field>
				<Field label="Note" id="bank-note"><Input id="bank-note" bind:value={adjust.note} maxlength={300} placeholder="Goodwill credit for the outage" /></Field>
			</form>
			{#snippet footer()}
				<Button onclick={() => (adjust = null)}>Cancel</Button>
				<Button variant="primary" type="submit" form="bank-form" loading={busy}>Save</Button>
			{/snippet}
		</Modal>
	{/if}
{/if}
