<script lang="ts">
	import { currencies } from '#lib/billing/currency.js';
	import { moneyText, parseMoney } from '#lib/billing/money.js';
	import type { BillingSettings } from '#lib/billing/types.js';
	import { api } from '#lib/api.js';
	import type { Resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	let { res, onsaved }: { res: Resource<BillingSettings>; onsaved: () => void } = $props();
	const manage = $derived(allowed('billing.manage'));

	let form = $state({ currency: '', company_address: '', invoice_prefix: '', terms: '30', invoice_footer: '', rate: '' });
	let loaded = $state(false);
	$effect(() => {
		const s = res.data;
		if (s && !loaded) {
			loaded = true;
			form = {
				currency: s.currency, company_address: s.company_address, invoice_prefix: s.invoice_prefix, terms: String(s.invoice_terms_days),
				invoice_footer: s.invoice_footer, rate: moneyText(s.default_rate, s.currency)
			};
		}
	});
	let saving = $state(false);
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const cur = form.currency.trim().toUpperCase();
		if (!/^[A-Z]{3}$/.test(cur)) return toast.error('The currency is a three-letter ISO code, like USD or EUR.');
		const terms = Number(form.terms);
		if (!Number.isInteger(terms) || terms < 0 || terms > 365) return toast.error('Payment terms are 0–365 days.');
		const rate = form.rate.trim() ? parseMoney(form.rate, cur) : 0;
		if (rate === null || Number.isNaN(rate) || rate < 0) return toast.error('Enter the default hourly rate as an amount.');
		const body = { currency: cur, company_address: form.company_address, invoice_prefix: form.invoice_prefix, invoice_terms_days: terms, invoice_footer: form.invoice_footer, default_rate: rate };
		saving = true;
		const ok = await attempt(() => api.put('/settings/billing', body), 'Billing settings saved.');
		saving = false;
		if (ok) {
			loaded = false;
			onsaved();
		}
	}
</script>

<section class="card" aria-labelledby="bs-general-h">
	<header class="border-border border-b px-5 py-3">
		<h2 id="bs-general-h" class="font-semibold">Invoices</h2>
		<p class="text-muted text-xs">What every invoice carries, and the rate time bills at when nothing more specific applies.</p>
	</header>
	<Async res={res} compact>
		{#snippet children(s)}
			<form class="space-y-4 p-5" onsubmit={save}>
				<fieldset class="grid gap-3 sm:grid-cols-3" disabled={!manage}>
					<Field label="Currency" id="bs-currency" hint="Clients can be billed in their own.">
						<Input id="bs-currency" bind:value={form.currency} list="bs-currencies" maxlength={3} class="uppercase" autocomplete="off" />
						<datalist id="bs-currencies">{#each currencies as c (c)}<option value={c}></option>{/each}</datalist>
					</Field>
					<Field label="Default hourly rate ({form.currency || s.currency})" id="bs-rate">
						<Input id="bs-rate" inputmode="decimal" bind:value={form.rate} placeholder="0.00" />
					</Field>
					<Field label="Payment terms (days)" id="bs-terms">
						<Input id="bs-terms" type="number" min="0" max="365" step="1" bind:value={form.terms} />
					</Field>
					<Field label="Number prefix" id="bs-prefix" hint="Letters, digits, - _ /">
						<Input id="bs-prefix" bind:value={form.invoice_prefix} maxlength={10} placeholder="INV-" />
					</Field>
					<div class="sm:col-span-2">
						<span class="label">Next number</span>
						<p class="text-sm"><code>{s.next_number}</code> <span class="text-muted text-xs">· numbers are given out when invoices are finalised, without gaps.</span></p>
					</div>
					<Field label="Company address" id="bs-address" class="sm:col-span-3" hint="Printed at the top of every invoice.">
						<Textarea id="bs-address" rows={3} bind:value={form.company_address} maxlength={1000} />
					</Field>
					<Field label="Footer" id="bs-footer" class="sm:col-span-3" hint="Payment details, registration numbers.">
						<Textarea id="bs-footer" rows={3} bind:value={form.invoice_footer} maxlength={2000} />
					</Field>
				</fieldset>
				{#if manage}<div class="flex justify-end"><Button type="submit" variant="primary" loading={saving}>Save</Button></div>{/if}
			</form>
		{/snippet}
	</Async>
</section>
