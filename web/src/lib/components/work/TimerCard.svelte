<script lang="ts">
	import { Play, Square, Timer } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { clients, loadClients } from '#lib/scope.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import { entryTarget, workTypes } from '#lib/work/meta.js';
	import { clock, fmtMinutes, timeOf } from '#lib/work/time.js';
	import { elapsed, loadTimer, startTimer, stopTimer, timer } from '#lib/work/timer.svelte.js';
	import type { Project, TicketRef, TimeEntry, WorkType } from '#lib/work/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Segmented from '#lib/ui/Segmented.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';
	import TicketPicker from './TicketPicker.svelte';

	/** Start / stop the signed-in user's timer. `onchange` runs after either (to reload lists). */
	let { onchange }: { onchange?: (stopped: TimeEntry | null) => void } = $props();

	type Kind = 'ticket' | 'client' | 'project' | 'internal';
	let kind = $state<Kind>('ticket');
	let ticket = $state<TicketRef | null>(null);
	let client = $state('');
	let project = $state('');
	let types = $state<WorkType[]>([]);
	let projects = $state<Project[]>([]);
	let workType = $state('');
	let note = $state('');
	let busy = $state(false);

	// Stopping: what to record.
	let stopNote = $state('');
	let stopBillable = $state(true);
	let stopPublic = $state(false);
	let lastId = '';
	$effect(() => {
		const e = timer.entry;
		if (e && e.id !== lastId) {
			lastId = e.id;
			stopNote = e.note;
			stopBillable = e.billable;
			stopPublic = false;
		}
	});

	$effect(() => {
		loadTimer().catch(() => {});
		loadClients();
		workTypes()
			.then((t) => {
				types = t.filter((x) => x.active);
				if (!workType && types[0]) workType = [...types].sort((a, b) => Number(b.billable) - Number(a.billable) || a.position - b.position)[0].id;
			})
			.catch(() => {});
		api.get<Project[]>('/projects').then((p) => (projects = p)).catch(() => {});
	});

	async function start(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		const ok = await attempt(() =>
			startTimer({
				ticket_id: kind === 'ticket' ? ticket?.id : undefined,
				client_id: kind === 'client' ? client || undefined : undefined,
				project_id: kind === 'project' ? project || undefined : undefined,
				work_type_id: workType || undefined,
				note
			})
		);
		busy = false;
		if (ok) {
			note = '';
			onchange?.(null);
		}
	}

	async function stop(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		let done: TimeEntry | null = null;
		const ok = await attempt(async () => {
			done = await stopTimer({ note: stopNote, billable: stopBillable, public: stopPublic });
		});
		busy = false;
		if (ok) {
			const d = done as TimeEntry | null;
			if (d) toast.success(`Logged ${fmtMinutes(d.minutes)}.`);
			onchange?.(d);
		}
	}
	const t = $derived(timer.entry);
</script>

<section class="card" aria-labelledby="timer-h">
	<header class="panel-head">
		<h2 id="timer-h" class="panel-title flex items-center gap-2"><Timer class="text-muted size-4" aria-hidden="true" /> Timer</h2>
		{#if t}<span class="text-accent font-mono text-lg font-semibold tabular" role="timer" aria-label="Elapsed time">{clock(elapsed())}</span>{/if}
	</header>
	{#if !timer.loaded}
		<p class="text-muted px-4 py-3 text-sm">Loading…</p>
	{:else if t}
		<form class="space-y-3 p-4" onsubmit={stop}>
			<p class="text-sm">
				<span class="font-medium">{entryTarget(t)}</span>
				<span class="text-muted">· {t.work_type_name} · since {timeOf(t.started_at)}</span>
				{#if t.ticket_id}<a class="link ml-1 text-xs" href="/tickets/{t.ticket_id}">Open ticket</a>{/if}
			</p>
			<Field label="Note" id="timer-stop-note"><Input id="timer-stop-note" bind:value={stopNote} maxlength={10000} placeholder="What you did" /></Field>
			<div class="flex flex-wrap items-center gap-x-5 gap-y-2">
				<Switch bind:checked={stopBillable} disabled={!t.client_id}>Billable</Switch>
				{#if t.ticket_id}<Checkbox bind:checked={stopPublic}>Post the note to the ticket as a reply</Checkbox>{/if}
				<Button class="ml-auto" variant="danger" type="submit" icon={Square} loading={busy}>Stop</Button>
			</div>
		</form>
	{:else}
		<form class="space-y-3 p-4" onsubmit={start}>
			<Segmented
				label="What the timer is for"
				value={kind}
				onchange={(v) => (kind = v)}
				options={[
					{ value: 'ticket', label: 'Ticket' },
					{ value: 'client', label: 'Client' },
					{ value: 'project', label: 'Project' },
					{ value: 'internal', label: 'Internal' }
				]}
			/>
			{#if kind === 'ticket'}
				<Field label="Ticket" id="timer-ticket"><TicketPicker id="timer-ticket" bind:value={ticket} /></Field>
			{:else if kind === 'client'}
				<Field label="Client" id="timer-client"><Combobox id="timer-client" bind:value={client} items={clients.list.map((c) => ({ value: c.id, label: c.name }))} placeholder="Choose a client…" /></Field>
			{:else if kind === 'project'}
				<Field label="Project" id="timer-project">
					<Combobox id="timer-project" bind:value={project} items={projects.map((p) => ({ value: p.id, label: p.name, hint: p.client_name }))} placeholder="Choose a project…" />
				</Field>
			{/if}
			<div class="grid gap-3 sm:grid-cols-[12rem_1fr]">
				<Field label="Work type" id="timer-type"><Select id="timer-type" class="w-full" bind:value={workType} options={types.map((x) => ({ value: x.id, label: x.name }))} /></Field>
				<Field label="Note" id="timer-note"><Input id="timer-note" bind:value={note} maxlength={10000} placeholder="Optional" /></Field>
			</div>
			<div class="flex justify-end">
				<Button
					variant="primary"
					type="submit"
					icon={Play}
					loading={busy}
					disabled={(kind === 'ticket' && !ticket) || (kind === 'client' && !client) || (kind === 'project' && !project)}>Start timer</Button
				>
			</div>
		</form>
	{/if}
</section>
