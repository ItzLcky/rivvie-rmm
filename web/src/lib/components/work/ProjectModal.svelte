<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Technician } from '#lib/types.js';
	import { projectStatuses } from '#lib/work/meta.js';
	import { hours } from '#lib/work/time.js';
	import type { Project, ProjectStatus } from '#lib/work/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Creates a project (optionally for `clientId`) or edits `project`. `onsaved` gets its id. */
	let { project, clientId, onclose, onsaved }: { project?: Project; clientId?: string; onclose: () => void; onsaved?: (id: string) => void } = $props();

	const init = untrack(() => ({ project, clientId }));
	const p0 = init.project;
	let client = $state(p0?.client_id ?? init.clientId ?? '');
	let name = $state(p0?.name ?? '');
	let description = $state(p0?.description ?? '');
	let status = $state<ProjectStatus>(p0?.status ?? 'planned');
	let budget = $state(p0?.budget_minutes ? hours(p0.budget_minutes) : '');
	let start = $state(p0?.start_date ?? '');
	let due = $state(p0?.due_date ?? '');
	let owner = $state(p0?.owner_id ?? '');
	let techs = $state<Technician[]>([]);
	let saving = $state(false);
	let error = $state('');

	$effect(() => {
		loadClients();
		ticketMeta()
			.then((m) => (techs = m.technicians))
			.catch(() => {});
	});

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		const b = budget.trim() ? Number(budget.replace(',', '.')) : 0;
		if (!client) return void (error = 'Choose the client.');
		if (!name.trim()) return void (error = 'Give the project a name.');
		if (!isFinite(b) || b < 0) return void (error = 'The budget is a number of hours, like 40 or 12.5.');
		if (start && due && due < start) return void (error = "The due date can't be before the start.");
		const body = {
			client_id: client,
			name: name.trim(),
			description,
			status,
			budget_minutes: Math.round(b * 60),
			start_date: start || null,
			due_date: due || null,
			owner_id: owner || null,
			contract_id: p0?.contract_id ?? null
		};
		saving = true;
		let id = p0?.id ?? '';
		const ok = await attempt(async () => {
			if (p0) await api.put(`/projects/${p0.id}`, body);
			else id = (await api.post<{ id: string }>('/projects', body)).id;
		}, `${body.name} saved.`);
		saving = false;
		if (ok) {
			onsaved?.(id);
			onclose();
		}
	}
</script>

<Modal title={p0 ? `Edit ${p0.name}` : 'New project'} {onclose} size="lg">
	<form id="project-form" class="space-y-4" onsubmit={save} novalidate>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Client" id="pj-client" required hint={p0 ? "A project stays with its client." : undefined}>
				<Combobox id="pj-client" bind:value={client} disabled={!!p0} items={clients.list.map((c) => ({ value: c.id, label: c.name }))} placeholder="Choose a client…" />
			</Field>
			<Field label="Name" id="pj-name" required><Input id="pj-name" bind:value={name} maxlength={200} required placeholder="Office move" /></Field>
			<Field label="Status" id="pj-status">
				<Select id="pj-status" class="w-full" bind:value={status} options={projectStatuses.map((s) => ({ value: s.value, label: s.label }))} />
			</Field>
			<Field label="Owner" id="pj-owner">
				<Select id="pj-owner" class="w-full" bind:value={owner} options={[{ value: '', label: 'Nobody' }, ...techs.map((t) => ({ value: t.id, label: t.name }))]} />
			</Field>
			<Field label="Budget (hours)" id="pj-budget" hint="Leave empty for no budget.">
				<Input id="pj-budget" bind:value={budget} inputmode="decimal" placeholder="40" />
			</Field>
			<div class="grid grid-cols-2 gap-3">
				<Field label="Starts" id="pj-start"><Input id="pj-start" type="date" bind:value={start} /></Field>
				<Field label="Due" id="pj-due"><Input id="pj-due" type="date" bind:value={due} min={start || undefined} /></Field>
			</div>
		</div>
		<Field label="Description" id="pj-desc"><Textarea id="pj-desc" rows={5} bind:value={description} maxlength={20000} /></Field>
		{#if error}<p class="text-danger text-sm" role="alert">{error}</p>{/if}
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="project-form" loading={saving}>{p0 ? 'Save' : 'Create project'}</Button>
	{/snippet}
</Modal>
