<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { entryTarget, workTypes } from '#lib/work/meta.js';
	import { durationInput, fmtMinutes, fromLocal, localDay, localTime, parseDuration } from '#lib/work/time.js';
	import type { Project, TicketRef, TimeEntry, WorkType } from '#lib/work/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import TicketPicker from './TicketPicker.svelte';

	type Kind = 'ticket' | 'client' | 'project' | 'internal';
	/**
	 * Logs time by hand, or edits an entry (`entry`). `ticket` / `projectId` / `clientId` preset
	 * what it's for (and lock it); `userId` logs for someone else (approvers).
	 */
	let {
		entry,
		ticket,
		projectId,
		clientId,
		userId,
		day,
		onclose,
		onsaved
	}: {
		entry?: TimeEntry;
		ticket?: TicketRef;
		projectId?: string;
		clientId?: string;
		userId?: string;
		day?: string;
		onclose: () => void;
		onsaved?: (e: TimeEntry) => void;
	} = $props();

	// The editor works on a copy of what it was opened with.
	const init = untrack(() => ({ entry, ticket, projectId, clientId, day }));
	const original = init.entry;
	const editing = !!original;
	const locked = editing || !!init.ticket || !!init.projectId;
	let kind = $state<Kind>(init.ticket ? 'ticket' : init.projectId ? 'project' : init.clientId ? 'client' : 'ticket');
	let chosenTicket = $state<TicketRef | null>(init.ticket ?? null);
	let chosenClient = $state(init.clientId ?? '');
	let chosenProject = $state(init.projectId ?? '');
	let types = $state<WorkType[]>([]);
	let projects = $state<Project[]>([]);
	let workType = $state(original?.work_type_id ?? '');
	let spent = $state(durationInput(original?.minutes ?? null));
	const start = original ? new Date(original.started_at) : null;
	let date = $state(start ? localDay(start) : (init.day ?? localDay()));
	let time = $state(start ? localTime(start) : '');
	let billable = $state(original?.billable ?? true);
	let billableTouched = editing;
	let note = $state(original?.note ?? '');
	let pub = $state(false);
	let saving = $state(false);
	let error = $state('');

	const running = !!original && original.ended_at === null;
	const minutes = $derived(parseDuration(spent));
	const active = $derived(types.filter((t) => t.active || t.id === workType));
	const hasClient = $derived(
		kind === 'ticket' ? !!chosenTicket?.client_id || !!original?.client_id : kind === 'client' ? !!chosenClient : kind === 'project' ? true : false
	);

	$effect(() => {
		workTypes().then((t) => {
			types = t;
			if (!workType) {
				const first = t.filter((x) => x.active).sort((a, b) => Number(b.billable) - Number(a.billable) || a.position - b.position)[0];
				if (first) workType = first.id;
			}
			if (!billableTouched) billable = t.find((x) => x.id === workType)?.billable ?? true;
		});
		loadClients();
		if (!editing && !init.ticket) api.get<Project[]>('/projects').then((p) => (projects = p)).catch(() => {});
	});

	function setType(id: string) {
		workType = id;
		if (!billableTouched) billable = types.find((t) => t.id === id)?.billable ?? true;
	}

	function startedAt(): string | undefined {
		if (time) return fromLocal(date, time).toISOString();
		if (original) return fromLocal(date, localTime(new Date(original.started_at))).toISOString();
		if (date === localDay()) return undefined; // the server takes "minutes ago"
		return fromLocal(date, '09:00').toISOString();
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		if (!running && !minutes) {
			error = 'Enter the time spent, like 1.5, 1:30 or 45m.';
			return;
		}
		if (!running && minutes! > 1440) {
			error = 'An entry can be at most 24 hours.';
			return;
		}
		if (!editing && kind === 'ticket' && !chosenTicket) {
			error = 'Choose the ticket, or log it against a client, a project or as internal time.';
			return;
		}
		if (!editing && kind === 'client' && !chosenClient) {
			error = 'Choose the client.';
			return;
		}
		if (!editing && kind === 'project' && !chosenProject) {
			error = 'Choose the project.';
			return;
		}
		saving = true;
		let saved: TimeEntry | null = null;
		const ok = await attempt(async () => {
			if (editing) {
				saved = await api.put<TimeEntry>(`/time/${original!.id}`, {
					work_type_id: workType || undefined,
					started_at: startedAt(),
					minutes: running ? undefined : minutes,
					billable,
					note
				});
			} else {
				saved = await api.post<TimeEntry>('/time', {
					ticket_id: kind === 'ticket' ? chosenTicket?.id : undefined,
					client_id: kind === 'client' ? chosenClient : undefined,
					project_id: kind === 'project' ? chosenProject : init.projectId,
					work_type_id: workType || undefined,
					started_at: startedAt(),
					minutes,
					billable,
					note,
					public: kind === 'ticket' && pub,
					user_id: userId
				});
			}
		}, editing ? 'Time entry saved.' : `Logged ${fmtMinutes(minutes)}.`);
		saving = false;
		if (ok && saved) {
			onsaved?.(saved);
			onclose();
		}
	}
</script>

<Modal title={editing ? 'Edit time entry' : 'Log time'} description={original ? entryTarget(original) : undefined} {onclose} size="md">
	<form id="log-time" class="space-y-4" onsubmit={save} novalidate>
		{#if !locked}
			<fieldset>
				<legend class="label">For</legend>
				<Segmented
					label="What the time was for"
					value={kind}
					onchange={(v) => (kind = v)}
					options={[
						{ value: 'ticket', label: 'Ticket' },
						{ value: 'client', label: 'Client' },
						{ value: 'project', label: 'Project' },
						{ value: 'internal', label: 'Internal' }
					]}
				/>
			</fieldset>
		{/if}
		{#if !editing}
			{#if kind === 'ticket'}
				<Field label="Ticket" id="lt-ticket" required><TicketPicker id="lt-ticket" bind:value={chosenTicket} disabled={!!init.ticket} /></Field>
			{:else if kind === 'client'}
				<Field label="Client" id="lt-client" required>
					<Combobox id="lt-client" bind:value={chosenClient} items={clients.list.map((c) => ({ value: c.id, label: c.name }))} placeholder="Choose a client…" />
				</Field>
			{:else if kind === 'project'}
				<Field label="Project" id="lt-project" required>
					{#if init.projectId}
						<Input id="lt-project" value={projects.find((p) => p.id === init.projectId)?.name ?? 'This project'} disabled />
					{:else}
						<Combobox id="lt-project" bind:value={chosenProject} items={projects.map((p) => ({ value: p.id, label: p.name, hint: p.client_name }))} placeholder="Choose a project…" />
					{/if}
				</Field>
			{:else}
				<p class="hint">Internal time (training, admin) isn't billed to anyone.</p>
			{/if}
		{/if}

		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Work type" id="lt-type">
				<Select id="lt-type" class="w-full" value={workType} onchange={(e) => setType(e.currentTarget.value)} options={active.map((t) => ({ value: t.id, label: t.name }))} />
			</Field>
			<Field label="Time spent" id="lt-spent" required hint={running ? 'Still running; stop the timer to set it.' : minutes ? fmtMinutes(minutes) : '1.5, 1:30, 45m or 1h 30m'}>
				<Input id="lt-spent" bind:value={spent} disabled={running} inputmode="text" autocomplete="off" placeholder="1h 30m" invalid={!!spent && !minutes} />
			</Field>
			<Field label="Date" id="lt-date"><Input id="lt-date" type="date" bind:value={date} required /></Field>
			<Field label="Started at" id="lt-time" hint={editing ? undefined : 'Optional; today defaults to just now.'}><Input id="lt-time" type="time" bind:value={time} /></Field>
		</div>

		<Switch
			bind:checked={billable}
			disabled={!hasClient}
			onchange={() => (billableTouched = true)}>{hasClient ? 'Billable' : 'Billable (needs a client)'}</Switch
		>

		<Field label="Note" id="lt-note">
			<Textarea id="lt-note" rows={4} bind:value={note} maxlength={10000} placeholder="What you did" />
		</Field>
		{#if !editing && kind === 'ticket' && chosenTicket}
			<Checkbox bind:checked={pub}>Also post the note to the ticket as a reply</Checkbox>
		{/if}
		{#if error}<p class="text-danger text-sm" role="alert">{error}</p>{/if}
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="log-time" loading={saving}>{editing ? 'Save' : 'Log time'}</Button>
	{/snippet}
</Modal>
