<script lang="ts">
	import { Package, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { formatMoney, moneyText, parseMoney } from '#lib/billing/money.js';
	import type { Product, ProductKind } from '#lib/billing/types.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	let { currency }: { currency: string } = $props();
	const manage = $derived(allowed('billing.manage'));
	const products = resource(() => api.get<Product[]>('/products'));
	let showInactive = $state(false);

	type Draft = { id: string | null; sku: string; name: string; description: string; kind: ProductKind; cost: string; price: string; active: boolean };
	let edit = $state<Draft | null>(null);
	let saving = $state(false);
	function open(p?: Product) {
		edit = p
			? { id: p.id, sku: p.sku ?? '', name: p.name, description: p.description, kind: p.kind, cost: moneyText(p.cost, currency), price: moneyText(p.price, currency), active: p.active }
			: { id: null, sku: '', name: '', description: '', kind: 'one_off', cost: '', price: '', active: true };
	}
	function amount(text: string, what: string): number | undefined {
		if (!text.trim()) return 0;
		const v = parseMoney(text, currency);
		if (v === null || Number.isNaN(v) || v < 0) {
			toast.error(`Enter the ${what} as an amount.`);
			return undefined;
		}
		return v;
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const d = edit!;
		const cost = amount(d.cost, 'cost');
		const price = amount(d.price, 'price');
		if (cost === undefined || price === undefined) return;
		const body = { sku: d.sku.trim() || null, name: d.name.trim(), description: d.description, kind: d.kind, cost, price, active: d.active };
		saving = true;
		const ok = await attempt(() => (d.id ? api.put(`/products/${d.id}`, body) : api.post('/products', body)), `${body.name} saved.`);
		saving = false;
		if (ok) {
			edit = null;
			products.reload();
		}
	}
	async function remove(p: Product) {
		const ok = await confirmAction({ title: `Delete ${p.name}?`, message: 'Past charges and invoice lines keep their description. To stop selling it but keep it on file, switch it off instead.', confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/products/${p.id}`), `${p.name} deleted.`))) products.reload();
	}
	const margin = (p: Product) => (p.price && p.cost !== null ? Math.round(((p.price - p.cost) / p.price) * 100) : null);
</script>

<section class="card" aria-labelledby="bs-products-h">
	<header class="border-border flex flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="bs-products-h" class="font-semibold">Product catalog</h2>
			<p class="text-muted text-xs">Hardware, licences and services technicians can sell on tickets, and items for recurring contracts.</p>
		</div>
		<div class="flex items-center gap-3">
			<Switch bind:checked={showInactive}>Show inactive</Switch>
			{#if manage}<Button icon={Plus} onclick={() => open()}>Add product</Button>{/if}
		</div>
	</header>
	<Async res={products} compact>
		{#snippet children(all)}
			{@const list = all.filter((p) => showInactive || p.active)}
			{#if list.length}
				<div class="overflow-x-auto">
					<table class="table">
						<thead><tr><th>Product</th><th>Type</th><th class="text-right">Cost</th><th class="text-right">Price</th>{#if manage}<th><span class="sr-only">Actions</span></th>{/if}</tr></thead>
						<tbody>
							{#each list as p (p.id)}
								{@const m = margin(p)}
								<tr>
									<td class="min-w-48">
										<div class="font-medium">{p.name} {#if !p.active}<Badge>Inactive</Badge>{/if}</div>
										<div class="text-muted text-xs">{p.sku ?? ''}{p.sku && p.description ? ' · ' : ''}{p.description}</div>
									</td>
									<td class="whitespace-nowrap">{p.kind === 'recurring' ? 'Recurring' : 'One-off'}</td>
									<td class="text-right tabular whitespace-nowrap">{formatMoney(p.cost, currency)}</td>
									<td class="text-right tabular whitespace-nowrap">
										{formatMoney(p.price, currency)}
										{#if m !== null}<div class="text-muted text-xs">{m}% margin</div>{/if}
									</td>
									{#if manage}
										<td class="w-20 text-right whitespace-nowrap">
											<IconButton icon={Pencil} size="sm" label="Edit {p.name}" onclick={() => open(p)} />
											<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {p.name}" onclick={() => remove(p)} />
										</td>
									{/if}
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<EmptyState compact icon={Package} title={all.length ? 'No active products' : 'No products'} description={all.length ? undefined : 'Add what you sell so technicians can add it to tickets at the right price.'} />
			{/if}
		{/snippet}
	</Async>
</section>

{#if edit}
	<Modal title={edit.id ? `Edit ${edit.name}` : 'Add product'} onclose={() => (edit = null)}>
		<form id="product-form" class="space-y-3" onsubmit={save}>
			<div class="grid gap-3 sm:grid-cols-[1fr_10rem]">
				<Field label="Name" id="pr-name" required><Input id="pr-name" bind:value={edit.name} required maxlength={200} /></Field>
				<Field label="SKU" id="pr-sku"><Input id="pr-sku" bind:value={edit.sku} maxlength={60} /></Field>
			</div>
			<Field label="Description" id="pr-desc"><Textarea id="pr-desc" rows={2} bind:value={edit.description} /></Field>
			<div>
				<span class="label" id="pr-kind-l">Type</span>
				<Segmented label="Type" size="md" value={edit.kind} onchange={(v) => (edit!.kind = v)} options={[{ value: 'one_off', label: 'One-off' }, { value: 'recurring', label: 'Recurring' }]} />
			</div>
			<div class="grid grid-cols-2 gap-3">
				<Field label="Cost ({currency})" id="pr-cost" hint="What you pay."><Input id="pr-cost" inputmode="decimal" bind:value={edit.cost} placeholder="0.00" /></Field>
				<Field label="Price ({currency})" id="pr-price" hint="What the client pays."><Input id="pr-price" inputmode="decimal" bind:value={edit.price} placeholder="0.00" /></Field>
			</div>
			<Switch bind:checked={edit.active}>Active (can be sold)</Switch>
		</form>
		{#snippet footer()}
			<Button onclick={() => (edit = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="product-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
