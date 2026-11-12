<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Ban, BadgeCheck, FileText, Lock, Pencil, Plus, ReceiptText, Send, Stamp, Trash2, Undo2, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { day, invoiceTitle, lineKindLabels, period } from '#lib/billing/meta.js';
	import { formatMoney, formatQuantity, lineAmount, moneyText, parseMoney, parseQuantity } from '#lib/billing/money.js';
	import type { InvoiceDetail, InvoiceLine } from '#lib/billing/types.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Badge from '#lib/ui/Badge.svelte';
	import Button, { buttonBase, buttonSizes, buttonVariants } from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import InvoiceBadges from '#lib/components/billing/InvoiceBadges.svelte';

	const id = $derived(page.params.id!);
	const inv = resource(() => api.get<InvoiceDetail>(`/invoices/${id}`), { keep: false });
	const manage = $derived(allowed('billing.manage'));
	let busy = $state(false);

	// --- draft details ---------------------------------------------------------------------------
	let details = $state({ notes: '', issue_date: '', due_date: '' });
	let detailsFor = '';
	$effect(() => {
		const i = inv.data;
		if (i && detailsFor !== `${i.id}:${i.status}`) {
			detailsFor = `${i.id}:${i.status}`;
			details = { notes: i.notes, issue_date: i.issue_date, due_date: i.due_date };
		}
	});
	const detailsDirty = $derived(!!inv.data && (details.notes !== inv.data.notes || details.issue_date !== inv.data.issue_date || details.due_date !== inv.data.due_date));
	async function saveDetails(e: SubmitEvent) {
		e.preventDefault();
		if (details.due_date < details.issue_date) return toast.error('The due date can’t be before the issue date.');
		busy = true;
		const ok = await attempt(() => api.patch(`/invoices/${id}`, details), 'Draft saved.');
		busy = false;
		if (ok) {
			detailsFor = '';
			inv.reload();
		}
	}

	// --- lines -----------------------------------------------------------------------------------
	let line = $state<{ id: string | null; description: string; qty: string; price: string } | null>(null);
	const lineError = $derived.by(() => {
		if (!line || !inv.data) return '';
		const q = parseQuantity(line.qty);
		const p = parseMoney(line.price, inv.data.currency);
		if (line.qty.trim() && (q === null || q === 0)) return 'Quantity must be a number other than zero.';
		if (line.price.trim() && (p === null || Number.isNaN(p))) return 'Enter the unit price as a number.';
		return '';
	});
	const linePreview = $derived.by(() => {
		if (!line || !inv.data) return null;
		const q = parseQuantity(line.qty);
		const p = parseMoney(line.price, inv.data.currency);
		return q !== null && p !== null && !Number.isNaN(p) ? lineAmount(q, p) : null;
	});
	function editLine(l?: InvoiceLine) {
		const cur = inv.data!.currency;
		line = l ? { id: l.id, description: l.description, qty: formatQuantity(l.quantity_milli), price: moneyText(l.unit_price, cur) } : { id: null, description: '', qty: '1', price: '' };
	}
	async function saveLine(e: SubmitEvent) {
		e.preventDefault();
		const l = line!;
		const q = parseQuantity(l.qty);
		const p = parseMoney(l.price, inv.data!.currency);
		if (q === null || q === 0 || p === null || Number.isNaN(p)) return toast.error(lineError || 'Enter a quantity and a unit price.');
		const body = { description: l.description.trim(), quantity_milli: q, unit_price: p };
		busy = true;
		const ok = await attempt(() => (l.id ? api.put(`/invoices/${id}/lines/${l.id}`, body) : api.post(`/invoices/${id}/lines`, body)));
		busy = false;
		if (ok) {
			line = null;
			inv.reload();
		}
	}
	async function removeLine(l: InvoiceLine) {
		const ok = await confirmAction({
			title: 'Remove this line?',
			message: l.kind === 'manual' ? l.description : `${l.description}. What it billed (time, products or the contract cycle) goes back to the next invoice run.`,
			confirmLabel: 'Remove',
			danger: true
		});
		if (ok && (await attempt(() => api.del(`/invoices/${id}/lines/${l.id}`)))) inv.reload();
	}

	// --- lifecycle -------------------------------------------------------------------------------
	async function act(path: string, success: string, after?: (r: Record<string, unknown>) => void) {
		busy = true;
		let res: Record<string, unknown> = {};
		const ok = await attempt(async () => {
			res = await api.post<Record<string, unknown>>(`/invoices/${id}/${path}`);
		}, success);
		busy = false;
		if (ok) after ? after(res) : inv.reload();
	}
	async function finalise() {
		const i = inv.data!;
		const ok = await confirmAction({
			title: `Finalise this ${i.kind === 'credit_note' ? 'credit note' : 'invoice'}?`,
			message: `It gets the next invoice number (numbering is permanent, with no gaps) and can’t be changed afterwards: corrections need a credit note. Total ${formatMoney(i.total, i.currency)}.`,
			confirmLabel: 'Finalise'
		});
		if (ok) act('finalise', 'Finalised.');
	}
	async function markPaid() {
		const i = inv.data!;
		if (await confirmAction({ title: `Mark ${i.number} paid?`, message: `${formatMoney(i.total, i.currency)} from ${i.client_name}.`, confirmLabel: 'Mark paid' })) act('paid', `${i.number} marked paid.`);
	}
	async function voidIt() {
		const i = inv.data!;
		const ok = await confirmAction({
			title: `Void ${i.number}?`,
			message: 'The number stays used and what it billed is not released. To bill it again, issue a credit note instead.',
			confirmLabel: 'Void',
			danger: true
		});
		if (ok) act('void', `${i.number} voided.`);
	}
	async function credit() {
		const i = inv.data!;
		const ok = await confirmAction({ title: `Credit ${i.number}?`, message: 'Creates a draft credit note reversing every line. Edit it down for a partial credit, then finalise it.', confirmLabel: 'Create credit note' });
		if (ok) act('credit', 'Draft credit note created.', (r) => goto(`/billing/${r.id}`));
	}
	async function removeDraft() {
		const ok = await confirmAction({ title: 'Delete this draft?', message: 'What it billed goes back to the next invoice run.', confirmLabel: 'Delete draft', danger: true });
		if (ok && (await attempt(() => api.del(`/invoices/${id}`), 'Draft deleted.'))) goto('/billing', { replace: true });
	}

	// --- send ------------------------------------------------------------------------------------
	let send = $state<{ to: string[]; message: string } | null>(null);
	function openSend() {
		const r = inv.data!.recipients;
		send = { to: r.length ? [...r] : [''], message: '' };
	}
	async function doSend(e: SubmitEvent) {
		e.preventDefault();
		const to = send!.to.map((t) => t.trim()).filter(Boolean);
		if (!to.length) return toast.error('Add at least one email address.');
		busy = true;
		let sent: string[] = [];
		const ok = await attempt(async () => {
			sent = (await api.post<{ to: string[] }>(`/invoices/${id}/send`, { to, message: send!.message.trim() || null })).to;
		});
		busy = false;
		if (ok) {
			toast.success(`Sent to ${sent.join(', ')}.`);
			send = null;
			inv.reload();
		}
	}

	const linkBtn = (variant: 'secondary' | 'ghost' = 'secondary') => [buttonBase, buttonVariants[variant], buttonSizes.md].join(' ');
	const pdfHref = $derived(`/api/invoices/${id}/pdf`);
</script>

<svelte:head><title>{inv.data ? invoiceTitle(inv.data) : 'Invoice'}</title></svelte:head>

{#if !allowed('billing.read')}
	<PageHeader title="Invoice" crumbs={[{ label: 'Invoices', href: '/billing' }]} />
	<div class="card"><EmptyState icon={Lock} title="No access to billing" /></div>
{:else if inv.error}
	<PageHeader title="Invoice" crumbs={[{ label: 'Invoices', href: '/billing' }]} />
	<div class="card"><ErrorState error={inv.error} onretry={() => inv.reload()} /></div>
{:else if !inv.data}
	<div class="space-y-4"><Skeleton class="h-10 w-72" /><Skeleton class="h-40 w-full" /><Skeleton class="h-64 w-full" /></div>
{:else}
	{@const i = inv.data}
	{@const draft = i.status === 'draft'}
	{@const issued = i.status === 'finalised' || i.status === 'sent'}
	<PageHeader
		title={invoiceTitle(i)}
		crumbs={[{ label: 'Invoices', href: '/billing' }, { label: invoiceTitle(i) }]}
		menu={manage
			? [
					...(draft ? [{ label: 'Delete draft', icon: Trash2, danger: true, onSelect: removeDraft }] : []),
					...(i.kind === 'invoice' && (issued || i.status === 'paid') ? [{ label: 'Create credit note', icon: Undo2, onSelect: credit }] : []),
					...(issued ? [{ label: 'Void', icon: Ban, danger: true, onSelect: voidIt }] : [])
				]
			: []}
	>
		{#snippet meta()}<InvoiceBadges invoice={i} />{/snippet}
		{#snippet subtitle()}
			<a href="/clients/{i.client_id}" class="hover:text-fg hover:underline">{i.client_name}</a>
			<span>{formatMoney(i.total, i.currency)}</span>
			{#if i.credit_of}<span>Credit for <a href="/billing/{i.credit_of}" class="hover:text-fg hover:underline">{i.credit_of_number ?? 'an invoice'}</a></span>{/if}
		{/snippet}
		{#snippet actions()}
			<a class={linkBtn()} href={pdfHref} target="_blank" rel="noopener"><FileText />{draft ? 'Preview PDF' : 'Open PDF'}</a>
			{#if manage}
				{#if draft}
					<Button variant="primary" icon={Stamp} loading={busy} onclick={finalise} disabled={!i.lines.length}>Finalise</Button>
				{:else if i.status !== 'void'}
					<Button icon={Send} onclick={openSend} variant={i.status === 'finalised' ? 'primary' : 'secondary'}>{i.sent_at ? 'Send again' : 'Send'}</Button>
					{#if issued && i.kind === 'invoice'}<Button icon={BadgeCheck} onclick={markPaid} loading={busy}>Mark paid</Button>{/if}
				{/if}
			{/if}
		{/snippet}
	</PageHeader>

	<div class="grid gap-5 lg:grid-cols-[1fr_20rem]">
		<div class="min-w-0 space-y-5">
			<section class="card" aria-labelledby="lines-h">
				<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
					<h2 id="lines-h" class="font-semibold">Lines</h2>
					{#if manage && draft}<Button size="sm" icon={Plus} onclick={() => editLine()}>Add line</Button>{/if}
				</header>
				{#if i.lines.length}
					<div class="overflow-x-auto">
						<table class="table">
							<thead>
								<tr>
									<th>Description</th>
									<th class="text-right">Qty</th>
									<th class="text-right">Unit price</th>
									<th class="text-right">Amount</th>
									{#if manage && draft}<th><span class="sr-only">Actions</span></th>{/if}
								</tr>
							</thead>
							<tbody>
								{#each i.lines as l (l.id)}
									<tr>
										<td class="min-w-48">
											<div>{l.description}</div>
											{#if l.kind !== 'manual'}<div class="text-muted text-xs">{lineKindLabels[l.kind]}{#if l.contract_id} · <a class="hover:text-fg hover:underline" href="/contracts/{l.contract_id}">contract</a>{/if}</div>{/if}
										</td>
										<td class="text-right tabular whitespace-nowrap">{formatQuantity(l.quantity_milli)}</td>
										<td class="text-right tabular whitespace-nowrap">{formatMoney(l.unit_price, i.currency)}</td>
										<td class="text-right font-medium tabular whitespace-nowrap">{formatMoney(l.amount, i.currency)}</td>
										{#if manage && draft}
											<td class="w-20 text-right whitespace-nowrap">
												<IconButton icon={Pencil} size="sm" label="Edit {l.description}" onclick={() => editLine(l)} />
												<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Remove {l.description}" onclick={() => removeLine(l)} />
											</td>
										{/if}
									</tr>
								{/each}
							</tbody>
							<tfoot>
								<tr>
									<th scope="row" colspan="3" class="text-right font-semibold">Total</th>
									<td class="text-right text-base font-semibold tabular whitespace-nowrap">{formatMoney(i.total, i.currency)}</td>
									{#if manage && draft}<td></td>{/if}
								</tr>
							</tfoot>
						</table>
					</div>
				{:else}
					<EmptyState compact icon={ReceiptText} title="No lines" description={draft ? 'Add a line by hand, or delete this draft and run invoices for the period.' : undefined} />
				{/if}
			</section>

			{#if draft && manage}
				<section class="card" aria-labelledby="draft-h">
					<header class="border-border border-b px-5 py-3"><h2 id="draft-h" class="font-semibold">Draft details</h2></header>
					<form class="space-y-3 p-5" onsubmit={saveDetails}>
						<div class="grid gap-3 sm:grid-cols-2">
							<Field label="Issue date" id="inv-issue"><Input id="inv-issue" type="date" bind:value={details.issue_date} required /></Field>
							<Field label="Due date" id="inv-due"><Input id="inv-due" type="date" bind:value={details.due_date} min={details.issue_date} required /></Field>
						</div>
						<Field label="Notes" id="inv-notes" hint="Printed on the invoice."><Textarea id="inv-notes" rows={3} bind:value={details.notes} maxlength={5000} /></Field>
						<div class="flex justify-end"><Button type="submit" variant="primary" loading={busy} disabled={!detailsDirty}>Save</Button></div>
					</form>
				</section>
			{:else if i.notes}
				<section class="card px-5 py-4" aria-labelledby="notes-h">
					<h2 id="notes-h" class="label">Notes</h2>
					<p class="text-sm whitespace-pre-wrap">{i.notes}</p>
				</section>
			{/if}
		</div>

		<aside class="space-y-5">
			<section class="card px-5 py-4" aria-labelledby="sum-h">
				<h2 id="sum-h" class="sr-only">Summary</h2>
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
					<dt class="text-muted">Client</dt>
					<dd><a href="/clients/{i.client_id}" class="hover:underline">{i.client_name}</a></dd>
					<dt class="text-muted">Issued</dt>
					<dd>{day(i.issue_date)}</dd>
					{#if i.kind === 'invoice'}
						<dt class="text-muted">Due</dt>
						<dd class={i.overdue ? 'text-danger font-medium' : ''}>{day(i.due_date)}</dd>
					{/if}
					{#if i.period_start}
						<dt class="text-muted">Period</dt>
						<dd>{period(i.period_start, i.period_end)}</dd>
					{/if}
					<dt class="text-muted">Currency</dt>
					<dd>{i.currency}</dd>
					{#if i.finalised_at}<dt class="text-muted">Finalised</dt><dd>{datetime(i.finalised_at)}</dd>{/if}
					{#if i.sent_at}<dt class="text-muted">Sent</dt><dd>{datetime(i.sent_at)}</dd>{/if}
					{#if i.paid_at}<dt class="text-muted">Paid</dt><dd>{datetime(i.paid_at)}</dd>{/if}
					{#if i.voided_at}<dt class="text-muted">Voided</dt><dd>{datetime(i.voided_at)}</dd>{/if}
				</dl>
			</section>

			<section class="card px-5 py-4" aria-labelledby="billto-h">
				<h2 id="billto-h" class="label">Bill to</h2>
				{#if i.bill_to}
					<p class="text-sm whitespace-pre-wrap">{i.bill_to}</p>
				{:else}
					<p class="text-muted text-sm">{i.client_name} and its billing address, frozen when the invoice is finalised.</p>
				{/if}
				{#if i.recipients.length}
					<h3 class="label mt-3">Billing contacts</h3>
					<ul class="text-sm">{#each i.recipients as r (r)}<li class="truncate">{r}</li>{/each}</ul>
				{/if}
			</section>

			{#if !draft}
				<section class="card px-5 py-4" aria-labelledby="acct-h">
					<h2 id="acct-h" class="label">Accounting</h2>
					{#if i.external?.error}
						<Badge tone="danger">Sync failed</Badge>
						<p class="text-danger mt-1 text-xs break-words">{i.external.error}</p>
						<p class="hint">It’s retried on the next sync (Settings → Billing).</p>
					{:else if i.external?.id}
						<p class="text-sm"><Badge tone="success">Synced</Badge> <span class="text-muted">{i.external.provider === 'qbo' ? 'QuickBooks' : i.external.provider === 'xero' ? 'Xero' : i.external.provider} · {i.external.id}</span></p>
						{#if i.external.synced_at}<p class="text-muted mt-1 text-xs">{datetime(i.external.synced_at)}</p>{/if}
					{:else}
						<p class="text-muted text-sm">Not in an accounting system{i.external?.provider ? ' yet' : ''}.</p>
					{/if}
				</section>
			{/if}
		</aside>
	</div>

	{#if line}
		<Modal title={line.id ? 'Edit line' : 'Add line'} size="md" onclose={() => (line = null)}>
			<form id="line-form" class="space-y-3" onsubmit={saveLine}>
				<Field label="Description" id="line-desc" required><Input id="line-desc" bind:value={line.description} required maxlength={500} /></Field>
				<div class="grid grid-cols-2 gap-3">
					<Field label="Quantity" id="line-qty" required hint="Negative for a discount."><Input id="line-qty" inputmode="decimal" bind:value={line.qty} required invalid={!!lineError && !!line.qty.trim()} /></Field>
					<Field label="Unit price ({i.currency})" id="line-price" required><Input id="line-price" inputmode="decimal" bind:value={line.price} required placeholder="0.00" /></Field>
				</div>
				{#if lineError}<p class="text-danger text-xs" role="alert">{lineError}</p>{/if}
				<p class="text-muted text-sm">Amount: <span class="text-fg font-medium tabular">{linePreview === null ? '–' : formatMoney(linePreview, i.currency)}</span></p>
			</form>
			{#snippet footer()}
				<Button onclick={() => (line = null)}>Cancel</Button>
				<Button variant="primary" type="submit" form="line-form" loading={busy}>Save</Button>
			{/snippet}
		</Modal>
	{/if}

	{#if send}
		<Modal title="Send {i.number}" description="Emails the PDF to these addresses." onclose={() => (send = null)}>
			<form id="send-form" class="space-y-4" onsubmit={doSend}>
				<fieldset>
					<legend class="label">To</legend>
					<div class="space-y-1.5">
						{#each send.to as _, n (n)}
							<div class="flex items-center gap-2">
								<Input type="email" aria-label="Recipient {n + 1}" class="min-w-0 flex-1" bind:value={send.to[n]} placeholder="accounts@client.example" />
								<IconButton icon={X} size="sm" label="Remove recipient {n + 1}" onclick={() => send!.to.splice(n, 1)} disabled={send.to.length === 1} />
							</div>
						{/each}
					</div>
					<Button size="sm" variant="ghost" icon={Plus} class="mt-1" onclick={() => send!.to.push('')} disabled={send.to.length >= 20}>Add recipient</Button>
					{#if !i.recipients.length}<p class="hint">The client has no billing contacts; mark one on its contacts to fill this in next time.</p>{/if}
				</fieldset>
				<Field label="Message" id="send-msg" hint="Optional; replaces the greeting.">
					<Textarea id="send-msg" rows={4} bind:value={send.message} maxlength={5000} placeholder="Hello," />
				</Field>
			</form>
			{#snippet footer()}
				<Button onclick={() => (send = null)}>Cancel</Button>
				<Button variant="primary" type="submit" form="send-form" icon={Send} loading={busy}>Send</Button>
			{/snippet}
		</Modal>
	{/if}
{/if}
