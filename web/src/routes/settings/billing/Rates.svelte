<script lang="ts">
	import { Users } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { formatMoney, moneyText, parseMoney } from '#lib/billing/money.js';
	import type { UserRates, WorkRole } from '#lib/billing/types.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';

	/** Per technician: work role, own billing rate, cost rate and weekly capacity. */
	let { currency, rolesVersion = 0 }: { currency: string; rolesVersion?: number } = $props();
	const manage = $derived(allowed('billing.manage'));

	type Row = { user: UserRates; role: string; rate: string; cost: string; hours: string; saved: string };
	let rows = $state<Row[]>([]);
	let roles = $state<WorkRole[]>([]);
	let loading = $state(true);
	let error = $state<Error | null>(null);
	let saving = $state<string | null>(null);
	const key = (r: Pick<Row, 'role' | 'rate' | 'cost' | 'hours'>) => [r.role, r.rate, r.cost, r.hours].join('|');

	async function load() {
		loading = !rows.length;
		error = null;
		try {
			const [users, rl] = await Promise.all([api.get<UserRates[]>('/billing/rates'), api.get<WorkRole[]>('/work-roles')]);
			roles = rl;
			rows = users.map((u) => {
				const r = { role: u.work_role_id ?? '', rate: moneyText(u.default_rate, currency), cost: moneyText(u.cost_rate, currency), hours: String(u.capacity_hours) };
				return { user: u, ...r, saved: key(r) };
			});
		} catch (e) {
			error = e as Error;
		}
		loading = false;
	}
	$effect(() => {
		void rolesVersion;
		if (currency) load();
	});

	function amount(text: string, what: string, optional: boolean): number | null | undefined {
		if (!text.trim()) return optional ? null : 0;
		const v = parseMoney(text, currency);
		if (v === null || Number.isNaN(v) || v < 0) {
			toast.error(`Enter the ${what} as an amount${optional ? ', or leave it empty' : ''}.`);
			return undefined;
		}
		return v;
	}
	async function save(r: Row) {
		const rate = amount(r.rate, 'billing rate', true);
		const cost = amount(r.cost, 'cost rate', false);
		const hours = Number(r.hours);
		if (rate === undefined || cost === undefined) return;
		if (!Number.isInteger(hours) || hours < 0 || hours > 168) return toast.error('Capacity is 0–168 hours a week.');
		saving = r.user.id;
		const ok = await attempt(
			() => api.put(`/users/${r.user.id}/rates`, { work_role_id: r.role || null, default_rate: rate, cost_rate: cost ?? 0, capacity_hours: hours }),
			`${r.user.name || r.user.email} saved.`
		);
		saving = null;
		if (ok) r.saved = key(r);
	}
	const roleRate = (id: string) => roles.find((x) => x.id === id);
</script>

<section class="card" aria-labelledby="bs-rates-h">
	<header class="border-border border-b px-5 py-3">
		<h2 id="bs-rates-h" class="font-semibold">Technician rates</h2>
		<p class="text-muted text-xs">
			Billing falls back from the contract, to the work type, to the role, to the technician’s own rate, to the default. The cost rate is what an hour costs you (for profitability); capacity is
			for utilisation.
		</p>
	</header>
	{#if error}
		<ErrorState {error} onretry={load} />
	{:else if loading}
		<div class="space-y-2 p-5"><Skeleton class="h-8 w-full" /><Skeleton class="h-8 w-full" /></div>
	{:else if !rows.length}
		<EmptyState compact icon={Users} title="No technicians" />
	{:else}
		<div class="overflow-x-auto">
			<table class="table">
				<thead>
					<tr>
						<th>Technician</th>
						<th>Work role</th>
						<th>Own rate / h ({currency})</th>
						<th>Cost / h ({currency})</th>
						<th>Hours a week</th>
						{#if manage}<th><span class="sr-only">Save</span></th>{/if}
					</tr>
				</thead>
				<tbody>
					{#each rows as r (r.user.id)}
						{@const name = r.user.name || r.user.email}
						{@const role = roleRate(r.role)}
						<tr>
							<td class="min-w-40">
								<div class="font-medium">{name}</div>
								<div class="text-muted text-xs">{r.user.email}</div>
							</td>
							<td>
								<Select aria-label="{name} work role" class="w-40" bind:value={r.role} disabled={!manage} options={[{ value: '', label: 'No role' }, ...roles.map((x) => ({ value: x.id, label: x.name }))]} />
								{#if role}<div class="text-muted mt-0.5 text-xs">{formatMoney(role.rate, currency)} / h</div>{/if}
							</td>
							<td><Input aria-label="{name} own rate" class="w-28" inputmode="decimal" bind:value={r.rate} placeholder="–" disabled={!manage} /></td>
							<td><Input aria-label="{name} cost rate" class="w-28" inputmode="decimal" bind:value={r.cost} placeholder="0.00" disabled={!manage} /></td>
							<td><Input aria-label="{name} hours a week" class="w-20" type="number" min="0" max="168" step="1" bind:value={r.hours} disabled={!manage} /></td>
							{#if manage}
								<td class="text-right">
									<Button size="sm" variant={key(r) !== r.saved ? 'primary' : 'secondary'} disabled={key(r) === r.saved} loading={saving === r.user.id} onclick={() => save(r)}>Save<span class="sr-only"> {name}</span></Button>
								</td>
							{/if}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</section>
