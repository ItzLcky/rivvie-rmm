<script lang="ts">
	import { untrack } from 'svelte';
	import { Clock, Package, Play, Plus, Square, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed, can, session } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { productCatalog } from '#lib/work/meta.js';
	import { loadCurrency, money } from '#lib/work/money.svelte.js';
	import { clock, dateText, fmtMinutes, localDay } from '#lib/work/time.js';
	import { elapsed, loadTimer, startTimer, stopTimer, timer } from '#lib/work/timer.svelte.js';
	import type { Charge, Product, TicketRef, TimeEntry } from '#lib/work/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import LogTimeModal from './LogTimeModal.svelte';

	/**
	 * The ticket sidebar's time and products: time logged on the ticket, a timer, "Log time", and
	 * catalog products sold on it. `locked` (closed or merged tickets) hides the actions.
	 * `number`/`subject` save a fetch when the Log time dialog opens.
	 */
	let {
		ticketId,
		clientId,
		locked = false,
		number,
		subject
	}: { ticketId: string; clientId: string | null; locked?: boolean; number?: number; subject?: string } = $props();

	const entries = resource(() => api.get<TimeEntry[]>(`/time?ticket_id=${ticketId}`));
	const charges = resource(() => api.get<Charge[]>(`/charges?ticket_id=${ticketId}`));
	let products = $state<Product[]>([]);
	const tech = $derived(can('technician'));
	const total = $derived((entries.data ?? []).reduce((n, e) => n + (e.minutes ?? 0), 0));
	const billable = $derived((entries.data ?? []).filter((e) => e.billable).reduce((n, e) => n + (e.minutes ?? 0), 0));
	const mine = $derived(timer.entry?.ticket_id === ticketId);
	const elsewhere = $derived(!!timer.entry && !mine);

	$effect(() => {
		loadCurrency();
		if (untrack(() => can('technician'))) {
			loadTimer().catch(() => {});
			productCatalog()
				.then((p) => (products = p.filter((x) => x.active)))
				.catch(() => {});
		}
	});

	// --- timer -----------------------------------------------------------------------------------
	let busy = $state(false);
	let stopNote = $state('');
	let stopPublic = $state(false);
	let stopping = $state(false);
	async function start() {
		if (elsewhere) {
			const ok = await confirmAction({ title: 'Stop the other timer?', message: 'Your timer is running on something else; it will be stopped and logged.', confirmLabel: 'Stop it and start here' });
			if (!ok) return;
		}
		busy = true;
		if (await attempt(() => startTimer({ ticket_id: ticketId }))) {
			stopNote = '';
			stopPublic = false;
			entries.reload();
		}
		busy = false;
	}
	async function stop(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		let done: TimeEntry | null = null;
		const ok = await attempt(async () => {
			done = await stopTimer({ note: stopNote.trim() || undefined, public: stopPublic });
		});
		busy = false;
		if (ok) {
			const d = done as TimeEntry | null;
			if (d) toast.success(`Logged ${fmtMinutes(d.minutes)}.`);
			stopping = false;
			stopNote = '';
			entries.reload();
		}
	}

	// --- log time --------------------------------------------------------------------------------
	let logging = $state<TicketRef | null>(null);
	async function openLog() {
		if (number != null) {
			logging = { id: ticketId, number, subject: subject ?? '', client_id: clientId, client_name: null };
			return;
		}
		await attempt(async () => {
			const t = await api.get<TicketRef>(`/tickets/${ticketId}`);
			logging = { id: t.id, number: t.number, subject: t.subject, client_id: t.client_id, client_name: t.client_name };
		});
	}

	// --- products --------------------------------------------------------------------------------
	let adding = $state(false);
	let product = $state('');
	let qty = $state('1');
	let saving = $state(false);
	async function addCharge(e: SubmitEvent) {
		e.preventDefault();
		const q = Number(qty.replace(',', '.'));
		if (!product || !isFinite(q) || q <= 0) {
			toast.error('Choose a product and a quantity above zero.');
			return;
		}
		saving = true;
		const name = products.find((p) => p.id === product)?.name ?? 'Product';
		if (await attempt(() => api.post('/charges', { ticket_id: ticketId, product_id: product, quantity_milli: Math.round(q * 1000) }), `${name} added.`)) {
			adding = false;
			product = '';
			qty = '1';
			charges.reload();
		}
		saving = false;
	}
	async function removeCharge(c: Charge) {
		const ok = await confirmAction({ title: `Remove ${c.description}?`, confirmLabel: 'Remove', danger: true });
		if (ok && (await attempt(() => api.del(`/charges/${c.id}`), 'Removed.'))) charges.reload();
	}
	const canRemove = (c: Charge) => !c.invoiced && !locked && (allowed('billing.manage') || c.created_by_name === session.user?.name);
	const quantity = (m: number) => new Intl.NumberFormat(undefined, { maximumFractionDigits: 3 }).format(m / 1000);
	const price = (p: Product) => (p.price != null ? ` · ${money(p.price)}` : '');
</script>

<section class="card" aria-labelledby="tt-time-h">
	<header class="panel-head">
		<h2 id="tt-time-h" class="panel-title flex items-center gap-2"><Clock class="text-muted size-4" aria-hidden="true" /> Time</h2>
		<span class="text-sm tabular"><span class="font-semibold">{fmtMinutes(total)}</span>{#if billable && billable !== total}<span class="text-muted"> · {fmtMinutes(billable)} billable</span>{/if}</span>
	</header>

	{#if tech && !locked}
		<div class="border-border border-b px-4 py-3">
			{#if mine}
				{#if stopping}
					<form class="space-y-2" onsubmit={stop}>
						<Field label="Note" id="tt-stop-note"><Input id="tt-stop-note" bind:value={stopNote} maxlength={10000} placeholder={timer.entry?.note || 'What you did'} /></Field>
						<Checkbox bind:checked={stopPublic}>Post the note as a reply</Checkbox>
						<div class="flex justify-end gap-2">
							<Button size="sm" onclick={() => (stopping = false)}>Back</Button>
							<Button size="sm" variant="danger" type="submit" icon={Square} loading={busy}>Stop and log</Button>
						</div>
					</form>
				{:else}
					<div class="flex items-center gap-2">
						<span class="text-accent font-mono text-base font-semibold tabular" role="timer" aria-label="Timer on this ticket">{clock(elapsed())}</span>
						<span class="text-muted text-xs">running</span>
						<Button class="ml-auto" size="sm" variant="danger" icon={Square} onclick={() => (stopping = true)}>Stop</Button>
					</div>
				{/if}
			{:else}
				<div class="flex flex-wrap gap-2">
					<Button size="sm" icon={Play} loading={busy} onclick={start} title={elsewhere ? 'Stops the timer that is running on something else' : undefined}>Start timer</Button>
					<Button size="sm" icon={Plus} onclick={openLog}>Log time</Button>
				</div>
				{#if elsewhere}<p class="hint">Your timer is running elsewhere ({clock(elapsed())}).</p>{/if}
			{/if}
		</div>
	{/if}

	{#if entries.error && !entries.data}
		<p class="text-danger px-4 py-3 text-sm" role="alert">{entries.error.message} <button class="underline" onclick={() => entries.reload()}>Retry</button></p>
	{:else if entries.data?.length}
		<ul class="divide-border max-h-80 divide-y overflow-y-auto">
			{#each entries.data as e (e.id)}
				<li class="px-4 py-2 text-sm">
					<div class="flex items-baseline justify-between gap-2">
						<span class="min-w-0 truncate font-medium">{e.user_name}</span>
						<span class="tabular whitespace-nowrap">{e.ended_at === null ? 'running' : fmtMinutes(e.minutes)}</span>
					</div>
					<div class="text-muted flex justify-between gap-2 text-xs">
						<span class="truncate">{dateText(localDay(new Date(e.started_at)))} · {e.work_type_name}{e.billable ? '' : ' · not billable'}</span>
						{#if e.amount != null}<span class="tabular">{money(e.amount)}</span>{/if}
					</div>
					{#if e.note}<p class="text-muted mt-0.5 line-clamp-3 text-xs whitespace-pre-line">{e.note}</p>{/if}
				</li>
			{/each}
		</ul>
	{:else if entries.data}
		<p class="text-muted px-4 py-3 text-sm">No time logged yet.</p>
	{:else}
		<p class="text-muted px-4 py-3 text-sm" aria-busy="true">Loading…</p>
	{/if}
</section>

<section class="card mt-4" aria-labelledby="tt-prod-h">
	<header class="panel-head">
		<h2 id="tt-prod-h" class="panel-title flex items-center gap-2"><Package class="text-muted size-4" aria-hidden="true" /> Products sold</h2>
		{#if tech && !locked && clientId && !adding}<Button size="sm" variant="ghost" icon={Plus} onclick={() => (adding = true)} disabled={!products.length}>Add</Button>{/if}
	</header>
	{#if adding}
		<form class="border-border space-y-2 border-b px-4 py-3" onsubmit={addCharge}>
			<Field label="Product" id="tt-product">
				<Select
					id="tt-product"
					class="w-full"
					bind:value={product}
					options={[{ value: '', label: 'Choose…' }, ...products.map((p) => ({ value: p.id, label: `${p.name}${p.sku ? ` (${p.sku})` : ''}${price(p)}` }))]}
				/>
			</Field>
			<Field label="Quantity" id="tt-qty"><Input id="tt-qty" bind:value={qty} inputmode="decimal" class="w-28" /></Field>
			<div class="flex justify-end gap-2">
				<Button size="sm" onclick={() => (adding = false)}>Cancel</Button>
				<Button size="sm" variant="primary" type="submit" loading={saving}>Add</Button>
			</div>
		</form>
	{/if}
	{#if charges.error && !charges.data}
		<p class="text-danger px-4 py-3 text-sm" role="alert">{charges.error.message}</p>
	{:else if charges.data?.length}
		<ul class="divide-border divide-y">
			{#each charges.data as c (c.id)}
				<li class="flex items-start gap-2 px-4 py-2 text-sm">
					<div class="min-w-0 flex-1">
						<div class="truncate font-medium">{quantity(c.quantity_milli)} × {c.description}</div>
						<div class="text-muted text-xs">
							{dateText(c.day)}{#if c.created_by_name} · {c.created_by_name}{/if}{#if c.invoiced} · invoiced{/if}
							{#if c.unit_price != null} · {money(Math.round((c.unit_price * c.quantity_milli) / 1000))}{/if}
						</div>
					</div>
					{#if canRemove(c)}<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Remove {c.description}" onclick={() => removeCharge(c)} />{/if}
				</li>
			{/each}
		</ul>
	{:else if charges.data}
		<p class="text-muted px-4 py-3 text-sm">{clientId ? 'Nothing sold on this ticket.' : 'Set the ticket’s client to sell products on it.'}</p>
	{/if}
</section>

{#if logging}
	<LogTimeModal ticket={logging} onclose={() => (logging = null)} onsaved={() => entries.reload()} />
{/if}
