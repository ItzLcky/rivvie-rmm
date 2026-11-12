<script lang="ts">
	import { ArrowDown, ArrowUp, Plus, Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { moneyText, parseMoney } from '#lib/billing/money.js';
	import type { WorkType } from '#lib/billing/types.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Button from '#lib/ui/Button.svelte';
	import ErrorState from '#lib/ui/ErrorState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Skeleton from '#lib/ui/Skeleton.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	/** Work types, edited as one ordered list and saved together. */
	let { currency }: { currency: string } = $props();
	const manage = $derived(allowed('billing.manage'));

	type Row = { key: number; id: string | null; name: string; rate: string; billable: boolean; active: boolean };
	let rows = $state<Row[]>([]);
	let saved = $state('');
	let error = $state<Error | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let next = 0;
	const snapshot = () => JSON.stringify(rows.map(({ key: _k, ...r }) => r));
	const dirty = $derived(!loading && snapshot() !== saved);

	async function load() {
		loading = true;
		error = null;
		try {
			const list = await api.get<WorkType[]>('/work-types');
			rows = list.map((w) => ({ key: next++, id: w.id, name: w.name, rate: moneyText(w.rate, currency || 'USD'), billable: w.billable, active: w.active }));
			saved = snapshot();
		} catch (e) {
			error = e as Error;
		}
		loading = false;
	}
	$effect(() => {
		if (currency) load();
	});

	function move(i: number, d: number) {
		const [r] = rows.splice(i, 1);
		rows.splice(i + d, 0, r);
	}
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const types: { id: string | null; name: string; rate: number | null; billable: boolean; active: boolean }[] = [];
		for (const r of rows) {
			if (!r.name.trim()) return toast.error('Every work type needs a name.');
			let rate: number | null = null;
			if (r.rate.trim()) {
				rate = parseMoney(r.rate, currency);
				if (rate === null || Number.isNaN(rate) || rate < 0) return toast.error(`Enter ${r.name}'s rate as an amount, or leave it empty.`);
			}
			types.push({ id: r.id, name: r.name.trim(), rate, billable: r.billable, active: r.active });
		}
		if (!types.length) return toast.error('Keep at least one work type.');
		saving = true;
		const ok = await attempt(() => api.put('/work-types', { types }), 'Work types saved.');
		saving = false;
		if (ok) load();
	}
</script>

<section class="card" aria-labelledby="bs-wt-h">
	<header class="border-border border-b px-5 py-3">
		<h2 id="bs-wt-h" class="font-semibold">Work types</h2>
		<p class="text-muted text-xs">
			What technicians pick when they log time. A rate here wins over the technician’s; leave it empty to use the work role or technician rate. Types with time logged can only be switched off.
		</p>
	</header>
	{#if error}
		<ErrorState {error} onretry={load} />
	{:else if loading}
		<div class="space-y-2 p-5"><Skeleton class="h-8 w-full" /><Skeleton class="h-8 w-full" /></div>
	{:else}
		<form onsubmit={save}>
			<div class="overflow-x-auto">
				<table class="table">
					<thead>
						<tr><th>Name</th><th>Rate per hour ({currency})</th><th>Billable</th><th>Active</th>{#if manage}<th><span class="sr-only">Order and remove</span></th>{/if}</tr>
					</thead>
					<tbody>
						{#each rows as r, i (r.key)}
							<tr>
								<td class="min-w-44"><Input aria-label="Work type {i + 1} name" bind:value={r.name} maxlength={60} disabled={!manage} /></td>
								<td><Input aria-label="{r.name || `Work type ${i + 1}`} rate" class="w-28" inputmode="decimal" bind:value={r.rate} placeholder="–" disabled={!manage} /></td>
								<td><Switch bind:checked={r.billable} label="{r.name} is billable" disabled={!manage} /></td>
								<td><Switch bind:checked={r.active} label="{r.name} is active" disabled={!manage} /></td>
								{#if manage}
									<td class="text-right whitespace-nowrap">
										<IconButton icon={ArrowUp} size="sm" label="Move {r.name} up" disabled={i === 0} onclick={() => move(i, -1)} />
										<IconButton icon={ArrowDown} size="sm" label="Move {r.name} down" disabled={i === rows.length - 1} onclick={() => move(i, 1)} />
										<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Remove {r.name}" onclick={() => rows.splice(i, 1)} />
									</td>
								{/if}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if manage}
				<div class="border-border flex flex-wrap items-center justify-between gap-2 border-t px-5 py-3">
					<Button size="sm" variant="ghost" icon={Plus} onclick={() => rows.push({ key: next++, id: null, name: '', rate: '', billable: true, active: true })}>Add work type</Button>
					<div class="flex gap-2">
						{#if dirty}<Button size="sm" onclick={load}>Discard</Button>{/if}
						<Button size="sm" type="submit" variant="primary" loading={saving} disabled={!dirty}>Save work types</Button>
					</div>
				</div>
			{/if}
		</form>
	{/if}
</section>
