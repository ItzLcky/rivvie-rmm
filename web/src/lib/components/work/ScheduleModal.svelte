<script lang="ts">
	import { untrack } from 'svelte';
	import { Trash2 } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Technician } from '#lib/types.js';
	import { fromLocal, localDay, localTime } from '#lib/work/time.js';
	import type { Project, ScheduleEntry, TicketRef } from '#lib/work/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Combobox from '#lib/ui/Combobox.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';
	import TicketPicker from './TicketPicker.svelte';

	/**
	 * Creates or edits a schedule entry. `others` (the loaded entries) lets an edit warn about
	 * overlaps the way a create does from the server's answer.
	 */
	let {
		entry,
		technicians,
		preset,
		others = [],
		onclose,
		onsaved
	}: {
		entry?: ScheduleEntry;
		technicians: Technician[];
		preset?: { user_id?: string; day?: string; start?: string; end?: string; ticket?: TicketRef; project_id?: string };
		others?: ScheduleEntry[];
		onclose: () => void;
		onsaved?: () => void;
	} = $props();

	const init = untrack(() => ({ entry, preset }));
	const e0 = init.entry;
	const p0 = init.preset ?? {};
	const s0 = e0 ? new Date(e0.starts_at) : null;
	const x0 = e0 ? new Date(e0.ends_at) : null;

	let userId = $state(e0?.user_id ?? p0.user_id ?? '');
	let startDay = $state(s0 ? localDay(s0) : (p0.day ?? localDay()));
	let startTime = $state(s0 ? localTime(s0) : (p0.start ?? '09:00'));
	let endDay = $state(x0 ? localDay(x0) : (p0.day ?? localDay()));
	let endTime = $state(x0 ? localTime(x0) : (p0.end ?? '10:00'));
	let title = $state(e0?.title ?? '');
	let ticket = $state<TicketRef | null>(
		e0?.ticket_id ? { id: e0.ticket_id, number: e0.ticket_number ?? 0, subject: e0.ticket_subject ?? '', client_id: null, client_name: e0.client_name } : (p0.ticket ?? null)
	);
	let projectId = $state(e0?.project_id ?? p0.project_id ?? '');
	let notes = $state(e0?.notes ?? '');
	let projects = $state<Project[]>([]);
	let saving = $state(false);
	let error = $state('');

	$effect(() => {
		api.get<Project[]>('/projects?state=all').then((p) => (projects = p)).catch(() => {});
		if (!userId && technicians[0]) userId = technicians[0].id;
	});
	// Moving the start day drags a same-day end along.
	let lastStart = untrack(() => startDay);
	$effect(() => {
		const s = startDay;
		if (s !== lastStart) {
			if (endDay === lastStart || endDay < s) endDay = s;
			lastStart = s;
		}
	});

	async function save(ev: SubmitEvent) {
		ev.preventDefault();
		error = '';
		const starts = fromLocal(startDay, startTime);
		const ends = fromLocal(endDay, endTime);
		if (!(ends > starts)) {
			error = 'The end must be after the start.';
			return;
		}
		if (!title.trim() && !ticket && !projectId) {
			error = 'Give the entry a title, or link a ticket or project.';
			return;
		}
		const body = {
			user_id: userId,
			starts_at: starts.toISOString(),
			ends_at: ends.toISOString(),
			title: title.trim(),
			ticket_id: ticket?.id ?? null,
			project_id: projectId || null,
			notes
		};
		saving = true;
		let overlaps = 0;
		const ok = await attempt(async () => {
			if (e0) {
				await api.put(`/schedule/${e0.id}`, body);
				overlaps = others.filter((o) => o.id !== e0.id && o.user_id === userId && new Date(o.starts_at) < ends && new Date(o.ends_at) > starts).length;
			} else {
				overlaps = (await api.post<{ id: string; overlaps: number }>('/schedule', body)).overlaps;
			}
		}, e0 ? 'Schedule entry saved.' : 'Scheduled.');
		saving = false;
		if (ok) {
			if (overlaps > 0) {
				const who = technicians.find((t) => t.id === userId)?.name ?? 'They';
				toast.info(`${who} already has ${overlaps === 1 ? 'something' : `${overlaps} things`} booked at that time.`);
			}
			onsaved?.();
			onclose();
		}
	}
	async function remove() {
		if (!e0) return;
		const ok = await confirmAction({ title: 'Delete this schedule entry?', confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/schedule/${e0.id}`), 'Schedule entry deleted.'))) {
			onsaved?.();
			onclose();
		}
	}
</script>

<Modal title={e0 ? 'Edit schedule entry' : 'Schedule work'} {onclose} size="md">
	<form id="sched-form" class="space-y-4" onsubmit={save} novalidate>
		<Field label="Technician" id="se-user" required>
			<Select id="se-user" class="w-full" bind:value={userId} options={technicians.map((t) => ({ value: t.id, label: t.name }))} />
		</Field>
		<div class="grid grid-cols-2 gap-3">
			<Field label="Starts" id="se-sd"><Input id="se-sd" type="date" bind:value={startDay} required /></Field>
			<Field label="at" id="se-st"><Input id="se-st" type="time" bind:value={startTime} required /></Field>
			<Field label="Ends" id="se-ed"><Input id="se-ed" type="date" bind:value={endDay} required /></Field>
			<Field label="at" id="se-et"><Input id="se-et" type="time" bind:value={endTime} required /></Field>
		</div>
		<p class="hint -mt-2">Times are in your time zone ({Intl.DateTimeFormat().resolvedOptions().timeZone}).</p>
		<Field label="Title" id="se-title" hint="Optional when a ticket or project is linked.">
			<Input id="se-title" bind:value={title} maxlength={200} placeholder="Site visit, server migration…" />
		</Field>
		<Field label="Ticket" id="se-ticket"><TicketPicker id="se-ticket" bind:value={ticket} /></Field>
		<Field label="Project" id="se-project">
			<Combobox
				id="se-project"
				bind:value={projectId}
				clearable
				items={projects.map((p) => ({ value: p.id, label: p.name, hint: p.client_name }))}
				placeholder="None"
			/>
		</Field>
		<Field label="Notes" id="se-notes"><Textarea id="se-notes" rows={3} bind:value={notes} maxlength={5000} /></Field>
		{#if error}<p class="text-danger text-sm" role="alert">{error}</p>{/if}
	</form>
	{#snippet footer()}
		{#if e0}<Button variant="danger-ghost" icon={Trash2} class="mr-auto" onclick={remove}>Delete</Button>{/if}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="sched-form" loading={saving}>Save</Button>
	{/snippet}
</Modal>
