<script lang="ts">
	import { Plus, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { clientCurrency } from '#lib/billing/currency.js';
	import { contractKinds, cycles, deviceFilters, perCycle, today } from '#lib/billing/meta.js';
	import { formatQuantity, hoursToMinutes, minutesToHours, moneyText, parseMoney, parseQuantity } from '#lib/billing/money.js';
	import type { Contract, ContractDetail, ContractInput, ContractKind, Product, UserRates, WorkType } from '#lib/billing/types.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { SlaPolicy } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/**
	 * Create or edit a contract. Pass `contract` (the full detail, with items and rate
	 * overrides) to edit it, or `clientId` to add one for that client.
	 */
	let {
		contract,
		clientId,
		onclose,
		onsaved
	}: { contract?: ContractDetail | null; clientId?: string; onclose: () => void; onsaved?: (c: Contract) => void } = $props();

	// The editor is mounted per contract: it reads its props once.
	// svelte-ignore state_referenced_locally
	const c = contract ?? null;
	// svelte-ignore state_referenced_locally
	const lockedClient = !!(c || clientId);

	type Item = { product_id: string; description: string; qty: string; price: string };
	let form = $state({
		// svelte-ignore state_referenced_locally
		client_id: c?.client_id ?? clientId ?? '',
		name: c?.name ?? '',
		kind: (c?.kind ?? 'per_device') as ContractKind,
		start_date: c?.start_date ?? today(),
		end_date: c?.end_date ?? '',
		billing_cycle: c?.billing_cycle ?? 'monthly',
		price: '',
		device_filter: c?.device_filter ?? 'all',
		user_count: String(c?.user_count ?? 0),
		block_hours: minutesToHours(c?.block_minutes || null),
		overage: '',
		low_hours: minutesToHours(c?.low_balance_minutes || null),
		covered: [...(c?.covered_work_type_ids ?? [])],
		overrides: {} as Record<string, string>,
		sla_policy_id: c?.sla_policy_id ?? '',
		manager_id: c?.manager_id ?? '',
		notes: c?.notes ?? '',
		items: [] as Item[]
	});
	let currency = $state('');
	let errors = $state<Record<string, string>>({});
	let saving = $state(false);

	let workTypes = $state<WorkType[]>([]);
	let policies = $state<SlaPolicy[]>([]);
	let people = $state<UserRates[]>([]);
	let products = $state<Product[]>([]);

	$effect(() => {
		loadClients();
		api.get<WorkType[]>('/work-types').then((w) => (workTypes = w)).catch(toast.error);
		api.get<SlaPolicy[]>('/sla/policies').then((p) => (policies = p)).catch(() => {});
		api.get<UserRates[]>('/billing/rates').then((p) => (people = p)).catch(() => {});
		api.get<Product[]>('/products').then((p) => (products = p)).catch(() => {});
	});

	// Money fields follow the client's currency (its decimals); fill them once it's known.
	let filled = false;
	$effect(() => {
		const id = form.client_id;
		if (!id) return;
		clientCurrency(id).then((cur) => {
			if (form.client_id !== id) return;
			currency = cur;
			if (!filled) {
				filled = true;
				form.price = c ? moneyText(c.unit_price, cur) : '';
				form.overage = moneyText(c?.overage_rate ?? null, cur);
				form.overrides = Object.fromEntries((c?.rate_overrides ?? []).map((o) => [o.work_type_id, moneyText(o.rate, cur)]));
				form.items = (c?.items ?? []).map((i) => ({ product_id: i.product_id ?? '', description: i.description, qty: formatQuantity(i.quantity_milli), price: moneyText(i.unit_price, cur) }));
			}
		}, toast.error);
	});

	const kindHint = $derived(contractKinds.find((k) => k.value === form.kind)?.hint ?? '');
	const per = $derived(perCycle(form.billing_cycle));
	const cur = $derived(currency ? ` (${currency})` : '');
	const hasPrice = $derived(form.kind !== 'time_materials');
	const priceLabel = $derived(
		({ per_device: `Price per device each ${per}`, per_user: `Price per user each ${per}`, block_hours: `Price each ${per}`, recurring: `Fee each ${per}`, time_materials: '' } as const)[form.kind] + cur
	);
	const activeTypes = $derived(workTypes.filter((w) => w.active || form.covered.includes(w.id) || form.overrides[w.id]));

	function pickProduct(item: Item) {
		const p = products.find((x) => x.id === item.product_id);
		if (!p) return;
		if (!item.description.trim()) item.description = p.name;
		if (!item.price.trim() && p.price !== null) item.price = moneyText(p.price, currency);
	}

	function money(key: string, text: string, required = true): number | null {
		if (!text.trim()) {
			if (required) errors[key] = 'Enter an amount.';
			return null;
		}
		const v = parseMoney(text, currency);
		if (v === null || Number.isNaN(v) || v < 0) {
			errors[key] = 'Enter an amount of zero or more.';
			return null;
		}
		return v;
	}

	function build(): ContractInput | null {
		errors = {};
		const k = form.kind;
		const unit = hasPrice ? (money('price', form.price) ?? 0) : 0;
		let users = 0;
		if (k === 'per_user') {
			users = Number(form.user_count);
			if (!Number.isInteger(users) || users < 0) errors.user_count = 'Enter a whole number of users.';
		}
		let block = 0;
		let low = 0;
		let overage: number | null = null;
		if (k === 'block_hours') {
			block = hoursToMinutes(form.block_hours) ?? -1;
			if (block <= 0) errors.block_hours = 'Enter the hours bought each cycle.';
			low = form.low_hours.trim() ? (hoursToMinutes(form.low_hours) ?? -1) : 0;
			if (low < 0) errors.low_hours = 'Enter hours, or leave it empty.';
			overage = money('overage', form.overage, false);
		}
		const items =
			k === 'recurring'
				? form.items.map((i, n) => {
						const q = parseQuantity(i.qty);
						if (!i.description.trim()) errors[`item${n}`] = 'Describe the item.';
						else if (q === null || q <= 0) errors[`item${n}`] = 'Quantity must be more than zero.';
						const p = money(`item${n}`, i.price) ?? 0;
						return { product_id: i.product_id || null, description: i.description.trim(), quantity_milli: q ?? 0, unit_price: p };
					})
				: [];
		const rate_overrides = Object.entries(form.overrides)
			.filter(([, v]) => v.trim())
			.map(([work_type_id, v]) => ({ work_type_id, rate: money(`rate_${work_type_id}`, v) ?? 0 }));
		if (form.end_date && form.end_date < form.start_date) errors.end_date = 'The contract can’t end before it starts.';
		if (!form.client_id) errors.client_id = 'Choose a client.';
		if (Object.keys(errors).length) return null;
		return {
			client_id: form.client_id,
			name: form.name.trim(),
			kind: k,
			start_date: form.start_date,
			end_date: form.end_date || null,
			billing_cycle: form.billing_cycle,
			unit_price: unit,
			device_filter: k === 'per_device' ? form.device_filter : 'all',
			user_count: users,
			block_minutes: block,
			overage_rate: overage,
			low_balance_minutes: low,
			covered_work_type_ids: k === 'time_materials' ? [] : form.covered,
			sla_policy_id: form.sla_policy_id || null,
			manager_id: form.manager_id || null,
			notes: form.notes,
			items,
			rate_overrides
		};
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		if (!currency) return toast.error('Still loading the client’s currency; try again in a moment.');
		const body = build();
		if (!body) return toast.error('Check the highlighted fields.');
		saving = true;
		const out: { saved?: Contract } = {};
		const ok = await attempt(async () => {
			out.saved = c ? await api.put<Contract>(`/contracts/${c.id}`, body) : await api.post<Contract>('/contracts', body);
		}, `${body.name} saved.`);
		saving = false;
		if (ok && out.saved) onsaved?.(out.saved);
	}

	function toggleCovered(id: string, on: boolean) {
		form.covered = on ? [...form.covered, id] : form.covered.filter((x) => x !== id);
	}
</script>

<Modal title={c ? `Edit ${c.name}` : 'Add contract'} {onclose} size="lg">
	<form id="contract-form" class="space-y-5" onsubmit={save} novalidate>
		<div class="grid gap-3 sm:grid-cols-2">
			{#if !lockedClient}
				<Field label="Client" id="ct-client" required error={errors.client_id}>
					<Select id="ct-client" class="w-full" bind:value={form.client_id} options={[{ value: '', label: 'Choose a client…' }, ...clients.list.map((x) => ({ value: x.id, label: x.name }))]} />
				</Field>
			{/if}
			<Field label="Name" id="ct-name" required class={lockedClient ? 'sm:col-span-2' : ''}>
				<Input id="ct-name" bind:value={form.name} required maxlength={200} placeholder="Managed workstations" />
			</Field>
			<Field label="Type" id="ct-kind" hint={kindHint}>
				<Select id="ct-kind" class="w-full" bind:value={form.kind} options={contractKinds.map((k) => ({ value: k.value, label: k.label }))} />
			</Field>
			<Field label="Billing cycle" id="ct-cycle">
				<Select id="ct-cycle" class="w-full" bind:value={form.billing_cycle} options={cycles} />
			</Field>
			<Field label="Starts" id="ct-start" required>
				<Input id="ct-start" type="date" bind:value={form.start_date} required />
			</Field>
			<Field label="Ends" id="ct-end" hint="Leave empty for an open-ended contract." error={errors.end_date}>
				<Input id="ct-end" type="date" bind:value={form.end_date} min={form.start_date} invalid={!!errors.end_date} />
			</Field>
		</div>

		{#if form.kind !== 'time_materials'}
			<fieldset class="border-border grid gap-3 rounded-lg border p-3 sm:grid-cols-2">
				<legend class="label px-1">Pricing</legend>
				<Field label={priceLabel} id="ct-price" required error={errors.price}>
					<Input id="ct-price" inputmode="decimal" bind:value={form.price} placeholder="0.00" invalid={!!errors.price} />
				</Field>
				{#if form.kind === 'per_device'}
					<Field label="Devices billed" id="ct-filter">
						<Select id="ct-filter" class="w-full" bind:value={form.device_filter} options={deviceFilters} />
					</Field>
				{:else if form.kind === 'per_user'}
					<Field label="Users" id="ct-users" error={errors.user_count}>
						<Input id="ct-users" type="number" min="0" step="1" bind:value={form.user_count} invalid={!!errors.user_count} />
					</Field>
				{:else if form.kind === 'block_hours'}
					<Field label="Hours each {per}" id="ct-block" required error={errors.block_hours}>
						<Input id="ct-block" inputmode="decimal" bind:value={form.block_hours} placeholder="10" invalid={!!errors.block_hours} />
					</Field>
					<Field label="Overage rate per hour{cur}" id="ct-overage" hint="Time past the bank. Empty: the normal rates." error={errors.overage}>
						<Input id="ct-overage" inputmode="decimal" bind:value={form.overage} invalid={!!errors.overage} />
					</Field>
					<Field label="Warn below (hours)" id="ct-low" hint="The account manager is told when the bank runs this low." error={errors.low_hours}>
						<Input id="ct-low" inputmode="decimal" bind:value={form.low_hours} placeholder="2" invalid={!!errors.low_hours} />
					</Field>
					<Field label="Account manager" id="ct-manager" class="sm:col-span-2">
						<Select id="ct-manager" class="w-full" bind:value={form.manager_id} options={[{ value: '', label: 'Nobody' }, ...people.map((p) => ({ value: p.id, label: p.name || p.email }))]} />
					</Field>
				{/if}
			</fieldset>
		{/if}

		{#if form.kind === 'recurring'}
			<fieldset>
				<legend class="label">Items billed each {per}</legend>
				{#if form.items.length}
					<div class="space-y-2">
						{#each form.items as item, i (i)}
							<div class="border-border flex flex-wrap items-start gap-2 rounded-lg border p-2 sm:flex-nowrap sm:border-0 sm:p-0">
								<Select aria-label="Item {i + 1} product" class="w-full sm:w-40" bind:value={item.product_id} onchange={() => pickProduct(item)} options={[{ value: '', label: 'No product' }, ...products.filter((p) => p.active || p.id === item.product_id).map((p) => ({ value: p.id, label: p.name }))]} />
								<Input aria-label="Item {i + 1} description" class="min-w-0 flex-1 basis-40" bind:value={item.description} maxlength={300} placeholder="Description" invalid={!!errors[`item${i}`]} />
								<Input aria-label="Item {i + 1} quantity" class="w-20" inputmode="decimal" bind:value={item.qty} placeholder="1" />
								<Input aria-label="Item {i + 1} unit price{cur}" class="w-28" inputmode="decimal" bind:value={item.price} placeholder="0.00" />
								<IconButton icon={X} size="sm" label="Remove item {i + 1}" onclick={() => form.items.splice(i, 1)} />
							</div>
							{#if errors[`item${i}`]}<p class="text-danger text-xs" role="alert">{errors[`item${i}`]}</p>{/if}
						{/each}
					</div>
				{:else}
					<p class="text-muted text-sm">Only the fee. Add licences or services billed alongside it.</p>
				{/if}
				<Button size="sm" variant="ghost" icon={Plus} class="mt-1" onclick={() => form.items.push({ product_id: '', description: '', qty: '1', price: '' })}>Add item</Button>
			</fieldset>
		{/if}

		{#if form.kind !== 'time_materials'}
			<fieldset>
				<legend class="label">{form.kind === 'block_hours' ? 'Work that draws from the bank' : 'Work covered at no extra charge'}</legend>
				<p class="hint mb-1.5 mt-0">Anything else is billable on top.</p>
				<div class="grid gap-1.5 sm:grid-cols-2">
					{#each activeTypes as w (w.id)}
						<Checkbox checked={form.covered.includes(w.id)} onchange={(on: boolean) => toggleCovered(w.id, on)}>{w.name}</Checkbox>
					{/each}
				</div>
			</fieldset>
		{/if}

		<fieldset>
			<legend class="label">Hourly rates on this contract{cur}</legend>
			<p class="hint mb-1.5 mt-0">Override the normal rate for a work type; leave empty to keep it.</p>
			<div class="grid gap-2 sm:grid-cols-2">
				{#each activeTypes as w (w.id)}
					<div class="flex items-center gap-2">
						<label for="ct-rate-{w.id}" class="min-w-0 flex-1 truncate text-sm">{w.name}</label>
						<Input id="ct-rate-{w.id}" class="w-28" inputmode="decimal" placeholder={w.rate !== null && currency ? moneyText(w.rate, currency) : '–'} value={form.overrides[w.id] ?? ''} oninput={(e) => (form.overrides[w.id] = e.currentTarget.value)} invalid={!!errors[`rate_${w.id}`]} />
					</div>
				{/each}
			</div>
		</fieldset>

		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="SLA policy" id="ct-sla" hint="Its tickets use this policy before the client’s own.">
				<Select id="ct-sla" class="w-full" bind:value={form.sla_policy_id} options={[{ value: '', label: 'The client’s policy' }, ...policies.map((p) => ({ value: p.id, label: p.name }))]} />
			</Field>
		</div>
		<Field label="Notes" id="ct-notes">
			<Textarea id="ct-notes" rows={3} bind:value={form.notes} maxlength={10000} />
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="contract-form" loading={saving}>Save</Button>
	{/snippet}
</Modal>
