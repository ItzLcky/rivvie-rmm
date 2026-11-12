<script lang="ts">
	import { untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Technician } from '#lib/types.js';
	import { taskStatuses } from '#lib/work/meta.js';
	import { durationInput, parseDuration } from '#lib/work/time.js';
	import type { ProjectTask, TaskStatus } from '#lib/work/types.js';
	import Button from '#lib/ui/Button.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';

	let {
		projectId,
		task,
		phase,
		phases,
		technicians,
		onclose,
		onsaved
	}: { projectId: string; task?: ProjectTask; phase?: string; phases: string[]; technicians: Technician[]; onclose: () => void; onsaved?: () => void } = $props();

	const init = untrack(() => ({ task, phase }));
	const t0 = init.task;
	let ph = $state(t0?.phase ?? init.phase ?? '');
	let title = $state(t0?.title ?? '');
	let status = $state<TaskStatus>(t0?.status ?? 'todo');
	let estimate = $state(durationInput(t0?.estimate_minutes ?? null));
	let assignee = $state(t0?.assignee_id ?? '');
	let due = $state(t0?.due_date ?? '');
	let saving = $state(false);
	let error = $state('');

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		const est = estimate.trim() ? parseDuration(estimate) : 0;
		if (!title.trim()) return void (error = 'Give the task a title.');
		if (est == null) return void (error = 'The estimate is a duration like 4, 1.5 or 90m.');
		const body = { phase: ph.trim(), title: title.trim(), status, estimate_minutes: est, assignee_id: assignee || null, due_date: due || null, position: t0?.position };
		saving = true;
		const ok = await attempt(() => (t0 ? api.put(`/projects/${projectId}/tasks/${t0.id}`, body) : api.post(`/projects/${projectId}/tasks`, body)), t0 ? 'Task saved.' : 'Task added.');
		saving = false;
		if (ok) {
			onsaved?.();
			onclose();
		}
	}
</script>

<Modal title={t0 ? 'Edit task' : 'Add task'} {onclose} size="md">
	<form id="task-form" class="space-y-4" onsubmit={save} novalidate>
		<Field label="Title" id="tk-title" required><Input id="tk-title" bind:value={title} maxlength={300} required /></Field>
		<div class="grid gap-3 sm:grid-cols-2">
			<Field label="Phase" id="tk-phase" hint="Tasks are grouped by phase.">
				<Input id="tk-phase" bind:value={ph} maxlength={100} list="tk-phases" placeholder="Discovery, Build…" />
				<datalist id="tk-phases">{#each phases as p (p)}<option value={p}></option>{/each}</datalist>
			</Field>
			<Field label="Status" id="tk-status"><Select id="tk-status" class="w-full" bind:value={status} options={taskStatuses.map((s) => ({ value: s.value, label: s.label }))} /></Field>
			<Field label="Estimate" id="tk-est" hint={estimate && parseDuration(estimate) ? undefined : 'Hours, or 1h 30m'}><Input id="tk-est" bind:value={estimate} placeholder="4" /></Field>
			<Field label="Assignee" id="tk-assignee">
				<Select id="tk-assignee" class="w-full" bind:value={assignee} options={[{ value: '', label: 'Nobody' }, ...technicians.map((t) => ({ value: t.id, label: t.name }))]} />
			</Field>
			<Field label="Due" id="tk-due"><Input id="tk-due" type="date" bind:value={due} /></Field>
		</div>
		{#if error}<p class="text-danger text-sm" role="alert">{error}</p>{/if}
	</form>
	{#snippet footer()}
		<Button onclick={onclose}>Cancel</Button>
		<Button variant="primary" type="submit" form="task-form" loading={saving}>Save</Button>
	{/snippet}
</Modal>
