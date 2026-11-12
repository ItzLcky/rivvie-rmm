<script lang="ts">
	import { goto } from '$app/navigation';
	import { FilePlus2, Lock, Play, ReceiptText, Settings2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { day, invoiceFilters, invoiceTitle, lastMonth, period } from '#lib/billing/meta.js';
	import { formatMoney } from '#lib/billing/money.js';
	import type { BillingOverview, Invoice, InvoiceFilter } from '#lib/billing/types.js';
	import { num, plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { clientId, clients, currentClient, loadClients } from '#lib/scope.svelte.js';
	import { allowed, can } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { param, qs, setParams } from '#lib/url.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import DataTable, { type Column } from '#lib/ui/DataTable.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Tabs from '#lib/ui/Tabs.svelte';
	import InvoiceBadges from '#lib/components/billing/InvoiceBadges.svelte';

	const manage = $derived(allowed('billing.manage'));
	const scoped = $derived(currentClient());
	const status = $derived((invoiceFilters.some((f) => f.value === param('status')) ? param('status') : 'all') as InvoiceFilter | 'all');

	const list = resource(() => api.get<Invoice[]>(`/invoices${qs({ status: status === 'all' ? null : status, client_id: clientId() })}`));
	const overview = resource(() => api.get<BillingOverview>('/billing/overview'));
	$effect(() => {
		loadClients();
	});

	/** Sums of the listed invoices per currency (credit notes count negative already). */
	const totals = $derived.by(() => {
		const m = new Map<string, number>();
		for (const i of list.data ?? []) if (i.status !== 'void') m.set(i.currency, (m.get(i.currency) ?? 0) + i.total);
		return [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
	});

	// --- invoice run -----------------------------------------------------------------------------
	let run = $state<{ from: string; to: string; all: boolean; ids: string[] } | null>(null);
	let busy = $state(false);
	function openRun() {
		const [from, to] = lastMonth();
		run = { from, to, all: !clientId(), ids: clientId() ? [clientId()] : [] };
	}
	async function doRun(e: SubmitEvent) {
		e.preventDefault();
		const r = run!;
		if (r.to < r.from) return toast.error('The period ends before it starts.');
		if (!r.all && !r.ids.length) return toast.error('Choose at least one client, or run for all of them.');
		busy = true;
		let created: string[] = [];
		const ok = await attempt(async () => {
			created = (await api.post<{ created: string[] }>('/invoices/run', { from: r.from, to: r.to, client_ids: r.all ? null : r.ids })).created;
		});
		busy = false;
		if (!ok) return;
		run = null;
		if (created.length) {
			toast.success(`${plural(created.length, 'draft invoice')} created for ${period(r.from, r.to)}.`, created.length === 1 ? { href: { label: 'Open', href: `/billing/${created[0]}` } } : undefined);
			setParams({ status: 'draft' });
		} else toast.info(`Nothing to bill for ${period(r.from, r.to)}.`);
		list.reload();
		overview.reload();
	}

	// --- new blank draft -------------------------------------------------------------------------
	let blank = $state<{ client_id: string } | null>(null);
	async function doBlank(e: SubmitEvent) {
		e.preventDefault();
		if (!blank?.client_id) return toast.error('Choose a client.');
		busy = true;
		let id = '';
		const ok = await attempt(async () => {
			id = (await api.post<{ id: string }>('/invoices', { client_id: blank!.client_id })).id;
		});
		busy = false;
		if (ok) {
			blank = null;
			goto(`/billing/${id}`);
		}
	}
</script>

<svelte:head><title>Billing</title></svelte:head>

{#if !allowed('billing.read')}
	<PageHeader title="Billing" />
	<div class="card"><EmptyState icon={Lock} title="No access to billing" description="Ask an admin for the billing permission to see invoices." /></div>
{:else}
	<PageHeader title="Invoices" count={list.data?.length ?? null} description={scoped ? `${scoped.name}'s invoices and credit notes.` : 'Draft invoices from each billing run, and everything sent to clients.'}>
		{#snippet actions()}
			{#if can('admin')}<Button icon={Settings2} href="/settings/billing" variant="ghost">Settings</Button>{/if}
			{#if manage}
				<Button icon={FilePlus2} onclick={() => (blank = { client_id: clientId() })}>New draft</Button>
				<Button variant="primary" icon={Play} onclick={openRun}>Run invoices</Button>
			{/if}
		{/snippet}
	</PageHeader>

	{#if overview.data && (overview.data.currencies.length || overview.data.timesheets_pending)}
		<section aria-label="Billing overview" class="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
			{#each overview.data.currencies as c (c.currency)}
				<a href="/billing?status=unpaid" class="card hover:bg-hover/50 block px-4 py-3 transition-colors">
					<div class="text-muted text-xs font-medium">Outstanding · {c.currency}</div>
					<div class="mt-0.5 text-xl font-semibold tabular">{formatMoney(c.outstanding, c.currency)}</div>
					<div class="mt-0.5 text-xs">
						{#if c.overdue}<span class="text-danger font-medium">{formatMoney(c.overdue, c.currency)} overdue</span>{:else}<span class="text-muted">Nothing overdue</span>{/if}
						{#if c.drafts}<span class="text-muted"> · {plural(c.drafts, 'draft')}</span>{/if}
					</div>
				</a>
			{/each}
			<a class="card hover:bg-hover block px-4 py-3" href="/time/approvals">
				<div class="text-muted text-xs font-medium">Timesheets waiting for approval</div>
				<div class={['mt-0.5 text-xl font-semibold tabular', overview.data.timesheets_pending ? 'text-warning' : '']}>{num(overview.data.timesheets_pending)}</div>
				<div class="text-muted mt-0.5 text-xs">Only approved time is billed.</div>
			</a>
		</section>
	{/if}

	<Tabs label="Invoice status" class="mb-3" value={status} onchange={(v) => setParams({ status: v === 'all' ? null : v })} items={invoiceFilters} />

	{#if list.error && !list.data}
		<div class="card"><ErrorState error={list.error} onretry={() => list.reload()} /></div>
	{:else}
		{#snippet numberCell(i: Invoice)}
			<a href="/billing/{i.id}" class="font-medium hover:underline">{invoiceTitle(i)}</a>
			{#if i.credit_of_number}<div class="text-muted text-xs">Credit for {i.credit_of_number}</div>{/if}
		{/snippet}
		{#snippet clientCell(i: Invoice)}{i.client_name}{/snippet}
		{#snippet issueCell(i: Invoice)}<span class="whitespace-nowrap">{day(i.issue_date)}</span>{/snippet}
		{#snippet dueCell(i: Invoice)}<span class={['whitespace-nowrap', i.overdue && 'text-danger']}>{i.kind === 'credit_note' ? '–' : day(i.due_date)}</span>{/snippet}
		{#snippet periodCell(i: Invoice)}<span class="text-muted text-xs whitespace-nowrap">{i.period_start ? period(i.period_start, i.period_end) : '–'}</span>{/snippet}
		{#snippet statusCell(i: Invoice)}<InvoiceBadges invoice={i} />{/snippet}
		{#snippet totalCell(i: Invoice)}<span class={['tabular font-medium whitespace-nowrap', i.status === 'void' && 'text-muted line-through']}>{formatMoney(i.total, i.currency)}</span>{/snippet}

		<DataTable
			id="invoices"
			caption="Invoices"
			rows={list.data ?? []}
			key={(i) => i.id}
			loading={list.loading}
			busy={list.busy}
			rowHref={(i) => `/billing/${i.id}`}
			columns={[
				{ id: 'number', label: 'Number', cell: numberCell, hideable: false },
				...(scoped ? [] : [{ id: 'client', label: 'Client', cell: clientCell }]),
				{ id: 'issue', label: 'Issued', cell: issueCell, from: 'sm' },
				{ id: 'due', label: 'Due', cell: dueCell, from: 'md' },
				{ id: 'period', label: 'Period', cell: periodCell, from: 'lg', defaultHidden: true },
				{ id: 'status', label: 'Status', cell: statusCell, hideable: false },
				{ id: 'total', label: 'Total', cell: totalCell, align: 'right', hideable: false }
			] satisfies Column<Invoice>[]}
		>
			{#snippet empty()}
				{#if status !== 'all'}
					<EmptyState compact title="No invoices match" />
				{:else}
					<EmptyState icon={ReceiptText} title="No invoices yet" description="Run invoices for a period to draft one per client from contracts, approved time and products sold.">
						{#snippet action()}{#if manage}<Button variant="primary" icon={Play} onclick={openRun}>Run invoices</Button>{/if}{/snippet}
					</EmptyState>
				{/if}
			{/snippet}
			{#snippet footer()}
				{#if totals.length}
					<div class="flex flex-wrap justify-end gap-x-6 gap-y-1 px-4 py-2.5 text-sm">
						<span class="text-muted">{plural(list.data?.length ?? 0, 'invoice')} listed{status === 'all' ? ', excluding void' : ''}</span>
						{#each totals as [cur, sum] (cur)}<span class="font-semibold tabular">{formatMoney(sum, cur)}</span>{/each}
					</div>
				{/if}
			{/snippet}
		</DataTable>
	{/if}
{/if}

{#if run}
	<Modal title="Run invoices" description="Drafts one invoice per client with anything to bill in the period: contract cycles that start in it, approved time and products sold. Nothing is sent until you finalise and send each one." onclose={() => (run = null)}>
		<form id="run-form" class="space-y-4" onsubmit={doRun}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="From" id="run-from" required><Input id="run-from" type="date" bind:value={run.from} required /></Field>
				<Field label="To" id="run-to" required><Input id="run-to" type="date" bind:value={run.to} min={run.from} required /></Field>
			</div>
			<fieldset>
				<legend class="label">Clients</legend>
				<Checkbox bind:checked={run.all}>Every client with something to bill</Checkbox>
				{#if !run.all}
					<div class="border-border mt-2 max-h-56 space-y-1.5 overflow-y-auto rounded-lg border p-2">
						{#each clients.list as c (c.id)}
							<div>
								<Checkbox checked={run.ids.includes(c.id)} onchange={(on: boolean) => (run!.ids = on ? [...run!.ids, c.id] : run!.ids.filter((x) => x !== c.id))}>{c.name}</Checkbox>
							</div>
						{/each}
					</div>
					<p class="hint">{plural(run.ids.length, 'client')} chosen.</p>
				{/if}
			</fieldset>
		</form>
		{#snippet footer()}
			<Button onclick={() => (run = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="run-form" loading={busy} icon={Play}>Create drafts</Button>
		{/snippet}
	</Modal>
{/if}

{#if blank}
	<Modal title="New draft invoice" description="An empty draft to fill in by hand." size="sm" onclose={() => (blank = null)}>
		<form id="blank-form" onsubmit={doBlank}>
			<Field label="Client" id="blank-client" required>
				<Select id="blank-client" class="w-full" bind:value={blank.client_id} options={[{ value: '', label: 'Choose a client…' }, ...clients.list.map((c) => ({ value: c.id, label: c.name }))]} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (blank = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="blank-form" loading={busy}>Create draft</Button>
		{/snippet}
	</Modal>
{/if}
