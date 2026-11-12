<script lang="ts">
	import { Pencil, Plus, Trash2, UserCog } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { formatMoney, moneyText, parseMoney } from '#lib/billing/money.js';
	import type { WorkRole } from '#lib/billing/types.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { allowed } from '#lib/session.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';

	let { currency, onchange }: { currency: string; onchange?: () => void } = $props();
	const manage = $derived(allowed('billing.manage'));
	const roles = resource(() => api.get<WorkRole[]>('/work-roles'));

	let edit = $state<{ id: string | null; name: string; rate: string } | null>(null);
	let saving = $state(false);
	async function save(e: SubmitEvent) {
		e.preventDefault();
		const r = edit!;
		const rate = parseMoney(r.rate, currency);
		if (rate === null || Number.isNaN(rate) || rate < 0) return toast.error('Enter the hourly rate as an amount.');
		const body = { name: r.name.trim(), rate };
		saving = true;
		const ok = await attempt(() => (r.id ? api.put(`/work-roles/${r.id}`, body) : api.post('/work-roles', body)), `${body.name} saved.`);
		saving = false;
		if (ok) {
			edit = null;
			roles.reload();
			onchange?.();
		}
	}
	async function remove(r: WorkRole) {
		const ok = await confirmAction({ title: `Delete ${r.name}?`, message: r.users ? `${plural(r.users, 'technician')} fall back to their own rate.` : undefined, confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/work-roles/${r.id}`), `${r.name} deleted.`))) {
			roles.reload();
			onchange?.();
		}
	}
</script>

<section class="card" aria-labelledby="bs-roles-h">
	<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
		<div>
			<h2 id="bs-roles-h" class="font-semibold">Work roles</h2>
			<p class="text-muted text-xs">A rate per role (engineer, senior engineer); technicians in a role bill at it unless the work type has its own.</p>
		</div>
		{#if manage}<Button icon={Plus} onclick={() => (edit = { id: null, name: '', rate: '' })}>Add role</Button>{/if}
	</header>
	<Async res={roles} compact>
		{#snippet children(list)}
			{#if list.length}
				<ul class="divide-border divide-y">
					{#each list as r (r.id)}
						<li class="flex items-center gap-3 px-5 py-2.5 text-sm">
							<div class="min-w-0 flex-1">
								<span class="font-medium">{r.name}</span>
								<span class="text-muted text-xs"> · {currency ? formatMoney(r.rate, currency) : r.rate} / h · {plural(r.users, 'technician')}</span>
							</div>
							{#if manage}
								<IconButton icon={Pencil} size="sm" label="Edit {r.name}" onclick={() => (edit = { id: r.id, name: r.name, rate: moneyText(r.rate, currency) })} />
								<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {r.name}" onclick={() => remove(r)} />
							{/if}
						</li>
					{/each}
				</ul>
			{:else}
				<EmptyState compact icon={UserCog} title="No work roles" description="Optional: without roles, each technician bills at their own rate or the default." />
			{/if}
		{/snippet}
	</Async>
</section>

{#if edit}
	<Modal title={edit.id ? `Edit ${edit.name}` : 'Add work role'} size="sm" onclose={() => (edit = null)}>
		<form id="role-form" class="space-y-3" onsubmit={save}>
			<Field label="Name" id="role-name" required><Input id="role-name" bind:value={edit.name} required maxlength={100} placeholder="Senior engineer" /></Field>
			<Field label="Rate per hour ({currency})" id="role-rate" required><Input id="role-rate" inputmode="decimal" bind:value={edit.rate} required placeholder="0.00" /></Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (edit = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="role-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
