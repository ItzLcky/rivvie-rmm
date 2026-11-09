<script lang="ts">
	import { goto } from '$app/navigation';
	import { X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { levels, matrixPriority, priorities, ticketMeta, ticketNumber } from '#lib/servicedesk/tickets.svelte.js';
	import { session } from '#lib/session.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import type { AgentSummary, Contact, Page, Priority, Ticket, TicketMeta } from '#lib/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	/** Opens a ticket, optionally for a client, contact or agents already known (from their pages). */
	let {
		onclose,
		initial = {}
	}: {
		onclose: () => void;
		initial?: { clientId?: string; contactId?: string; agents?: Pick<AgentSummary, 'id' | 'hostname'>[]; subject?: string };
	} = $props();

	// svelte-ignore state_referenced_locally
	const init = initial;
	let clientId = $state(init.clientId ?? '');
	let contactId = $state(init.contactId ?? '');
	let subject = $state(init.subject ?? '');
	let description = $state('');
	let boardId = $state('');
	let typeId = $state('');
	let impact = $state<'' | 1 | 2 | 3>('');
	let urgency = $state<'' | 1 | 2 | 3>('');
	let priority = $state<Priority>(3);
	let assigneeId = $state('');
	let agents = $state<Pick<AgentSummary, 'id' | 'hostname'>[]>(init.agents ?? []);
	let busy = $state(false);

	let meta = $state<TicketMeta | null>(null);
	let contacts = $state<Contact[]>([]);
	let clientAgents = $state<AgentSummary[]>([]);
	$effect(() => {
		loadClients();
		ticketMeta().then((m) => {
			meta = m;
			boardId ||= m.boards[0]?.id ?? '';
		});
	});
	// The client's contacts and agents, for the pickers.
	$effect(() => {
		const c = clientId;
		contacts = [];
		clientAgents = [];
		if (!c) return;
		api.get<Contact[]>(`/contacts?client_id=${c}`).then((l) => {
			if (clientId !== c) return;
			contacts = l;
			if (!contactId && !init.contactId) contactId = l.find((x) => x.is_primary)?.id ?? '';
		});
		api.get<Page<AgentSummary>>(`/agents?client_id=${c}&limit=500&sort=hostname`).then((p) => clientId === c && (clientAgents = p.items));
	});
	$effect(() => {
		if (impact && urgency) priority = matrixPriority(impact, urgency);
	});

	const techs = $derived((meta?.technicians ?? []).filter((t) => !t.client_ids || (clientId && t.client_ids.includes(clientId))));
	const canTriage = $derived(session.user?.client_ids === null);

	function changeClient(v: string) {
		clientId = v;
		contactId = '';
		agents = [];
		if (assigneeId && !techs.some((t) => t.id === assigneeId)) assigneeId = '';
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		try {
			const t = await api.post<Ticket>('/tickets', {
				subject,
				description,
				client_id: clientId || null,
				contact_id: contactId || null,
				board_id: boardId || null,
				type_id: typeId || null,
				priority,
				impact: impact || null,
				urgency: urgency || null,
				assignee_id: assigneeId || null,
				agent_ids: agents.map((a) => a.id)
			});
			toast.success(`${ticketNumber(t.number)} opened.`);
			onclose();
			await goto(`/tickets/${t.id}`);
		} catch (err) {
			toast.error(err);
		} finally {
			busy = false;
		}
	}
</script>

<Modal title="New ticket" {onclose} size="lg">
	<form id="new-ticket" class="space-y-4" onsubmit={submit}>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Client" id="nt-client" required={!canTriage} hint={canTriage ? 'Leave empty to file it in triage.' : undefined}>
				<Combobox id="nt-client" value={clientId} clearable onchange={changeClient} placeholder="Choose a client…" items={clients.list.map((c) => ({ value: c.id, label: c.name }))} />
			</Field>
			<Field label="Contact" id="nt-contact" hint={clientId && !contacts.length ? 'This client has no contacts yet.' : undefined}>
				<Select
					id="nt-contact"
					class="w-full"
					bind:value={contactId}
					disabled={!clientId || !contacts.length}
					options={[{ value: '', label: 'No contact' }, ...contacts.map((c) => ({ value: c.id, label: c.email ? `${c.name} <${c.email}>` : c.name }))]}
				/>
			</Field>
		</div>
		<Field label="Subject" id="nt-subject" required>
			<!-- svelte-ignore a11y_autofocus -->
			<Input id="nt-subject" bind:value={subject} required maxlength={300} autofocus autocomplete="off" />
		</Field>
		<Field label="Description" id="nt-desc" hint="What the client asked for, or what's wrong. Visible to the client later in the portal.">
			<Textarea id="nt-desc" rows={5} bind:value={description} />
		</Field>
		<div class="grid gap-3 sm:grid-cols-3">
			<Field label="Board" id="nt-board">
				<Select id="nt-board" class="w-full" bind:value={boardId} options={(meta?.boards ?? []).map((b) => ({ value: b.id, label: b.name }))} />
			</Field>
			<Field label="Type" id="nt-type">
				<Select id="nt-type" class="w-full" bind:value={typeId} options={[{ value: '', label: 'None' }, ...(meta?.types ?? []).map((t) => ({ value: t.id, label: t.name }))]} />
			</Field>
			<Field label="Assignee" id="nt-assignee">
				<Select id="nt-assignee" class="w-full" bind:value={assigneeId} options={[{ value: '', label: 'Unassigned' }, ...techs.map((t) => ({ value: t.id, label: t.name }))]} />
			</Field>
		</div>
		<div class="grid gap-3 sm:grid-cols-3">
			<Field label="Impact" id="nt-impact">
				<Select id="nt-impact" class="w-full" bind:value={impact} options={[{ value: '', label: '–' }, ...levels.map((l) => ({ value: l.value, label: l.label }))]} />
			</Field>
			<Field label="Urgency" id="nt-urgency">
				<Select id="nt-urgency" class="w-full" bind:value={urgency} options={[{ value: '', label: '–' }, ...levels.map((l) => ({ value: l.value, label: l.label }))]} />
			</Field>
			<Field label="Priority" id="nt-priority" hint={impact && urgency ? 'From impact and urgency; you can override it.' : undefined}>
				<Select id="nt-priority" class="w-full" bind:value={priority} options={priorities.map((p) => ({ value: p.value, label: p.label }))} />
			</Field>
		</div>
		<Field label="Agents" id="nt-agent" hint="Their live state shows on the ticket, with their terminal, remote desktop and scripts one click away.">
			{#if agents.length}
				<ul class="mb-2 flex flex-wrap gap-1.5">
					{#each agents as a (a.id)}
						<li class="bg-sunken border-border inline-flex h-7 items-center gap-1 rounded-md border pr-1 pl-2 text-sm">
							{a.hostname}
							<button type="button" class="text-muted hover:text-fg rounded p-0.5" aria-label="Remove {a.hostname}" onclick={() => (agents = agents.filter((x) => x.id !== a.id))}><X class="size-3.5" /></button>
						</li>
					{/each}
				</ul>
			{/if}
			{#key agents.length}
			<Combobox
				id="nt-agent"
				value=""
				disabled={!clientId}
				placeholder={clientId ? 'Link an agent…' : 'Choose a client first'}
				items={clientAgents.filter((a) => !agents.some((x) => x.id === a.id)).map((a) => ({ value: a.id, label: a.hostname, hint: a.site_name }))}
				onchange={(v) => {
					const a = clientAgents.find((x) => x.id === v);
					if (a) agents = [...agents, a];
				}}
			/>
			{/key}
		</Field>
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="new-ticket" loading={busy} disabled={!subject.trim() || (!clientId && !canTriage)}>Open ticket</Button>
	{/snippet}
</Modal>
