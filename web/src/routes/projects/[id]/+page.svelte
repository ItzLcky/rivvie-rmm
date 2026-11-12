<script lang="ts">
	import { Clock, ListTodo, Pencil, Plus, Ticket, Trash2 } from '@lucide/svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { withClient } from '#lib/scope.svelte.js';
	import { ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { Technician } from '#lib/types.js';
	import { entryTarget, projectStatus, taskStatus, taskStatuses } from '#lib/work/meta.js';
	import { loadCurrency, money } from '#lib/work/money.svelte.js';
	import { dateText, fmtMinutes, localDay } from '#lib/work/time.js';
	import type { ProjectDetail, ProjectTask, TaskStatus, TimeEntry } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import BudgetBar from '#lib/components/work/BudgetBar.svelte';
	import BurnChart from '#lib/components/work/BurnChart.svelte';
	import LogTimeModal from '#lib/components/work/LogTimeModal.svelte';
	import ProjectModal from '#lib/components/work/ProjectModal.svelte';
	import TaskModal from '#lib/components/work/TaskModal.svelte';

	const id = $derived(page.params.id ?? '');
	const project = resource(() => api.get<ProjectDetail>(`/projects/${id}`), { keep: false });
	const entries = resource(() => api.get<TimeEntry[]>(`/time?project_id=${id}`));
	let techs = $state<Technician[]>([]);
	$effect(() => {
		loadCurrency();
		ticketMeta()
			.then((m) => (techs = m.technicians))
			.catch(() => {});
	});
	const tech = $derived(can('technician'));
	const today = localDay();

	let editing = $state(false);
	let task = $state<{ task?: ProjectTask; phase?: string } | null>(null);
	let logging = $state(false);

	function phases(tasks: ProjectTask[]): [string, ProjectTask[]][] {
		const m = new Map<string, ProjectTask[]>();
		for (const t of tasks) m.set(t.phase, [...(m.get(t.phase) ?? []), t]);
		return [...m.entries()];
	}
	function reload() {
		project.reload();
		entries.reload();
	}

	async function setStatus(t: ProjectTask, status: TaskStatus) {
		const body = { phase: t.phase, title: t.title, status, estimate_minutes: t.estimate_minutes, assignee_id: t.assignee_id, due_date: t.due_date, position: t.position };
		if (await attempt(() => api.put(`/projects/${id}/tasks/${t.id}`, body))) project.reload();
	}
	async function removeTask(t: ProjectTask) {
		const ok = await confirmAction({ title: `Delete “${t.title}”?`, message: t.ticket_id ? 'Its ticket stays open.' : undefined, confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/projects/${id}/tasks/${t.id}`), 'Task deleted.'))) project.reload();
	}
	let making = $state('');
	async function makeTicket(t: ProjectTask) {
		making = t.id;
		let ticket = '';
		const ok = await attempt(async () => {
			ticket = (await api.post<{ ticket_id: string }>(`/projects/${id}/tasks/${t.id}/ticket`)).ticket_id;
		});
		making = '';
		if (ok) {
			project.reload();
			goto(`/tickets/${ticket}`);
		}
	}
	async function removeProject(p: ProjectDetail) {
		const ok = await confirmAction({
			title: `Delete ${p.name}?`,
			message: 'Its tasks are deleted. Tickets and logged time stay, without the project.',
			confirmLabel: 'Delete project',
			danger: true,
			typeToConfirm: p.name
		});
		if (ok && (await attempt(() => api.del(`/projects/${p.id}`), `${p.name} deleted.`))) goto(withClient('/projects'));
	}
</script>

<Async res={project}>
	{#snippet children(p)}
		{@const s = projectStatus(p.status)}
		{@const groups = phases(p.task_list)}
		<PageHeader
			title={p.name}
			crumbs={[{ label: 'Projects', href: withClient('/projects') }, { label: p.name }]}
			menu={tech ? [{ label: 'Delete project', icon: Trash2, danger: true, onSelect: () => removeProject(p) }] : undefined}
		>
			{#snippet meta()}<Badge tone={s.tone}>{s.label}</Badge>{/snippet}
			{#snippet subtitle()}
				<a class="hover:underline" href="/clients/{p.client_id}">{p.client_name}</a>
				<span>Owner: {p.owner_name ?? 'nobody'}</span>
				{#if p.start_date || p.due_date}
					<span class={p.due_date && p.due_date < today && p.status !== 'done' && p.status !== 'cancelled' ? 'text-danger' : ''}>
						{dateText(p.start_date)} → {dateText(p.due_date)}
					</span>
				{/if}
			{/snippet}
			{#snippet actions()}
				{#if tech}
					<Button icon={Clock} onclick={() => (logging = true)}>Log time</Button>
					<Button icon={Pencil} onclick={() => (editing = true)}>Edit</Button>
				{/if}
			{/snippet}
		</PageHeader>

		<div class="grid gap-5 lg:grid-cols-[minmax(0,1fr)_22rem]">
			<div class="min-w-0 space-y-5">
				{#if p.description}
					<section class="card p-4" aria-label="Description"><p class="text-sm whitespace-pre-line">{p.description}</p></section>
				{/if}

				<section class="card" aria-labelledby="tasks-h">
					<header class="panel-head">
						<h2 id="tasks-h" class="panel-title">Tasks <span class="text-muted text-sm font-normal tabular">{p.tasks_done} / {p.tasks} done</span></h2>
						{#if tech}<Button size="sm" icon={Plus} onclick={() => (task = {})}>Add task</Button>{/if}
					</header>
					{#if !p.task_list.length}
						<EmptyState compact icon={ListTodo} title="No tasks yet" description="Break the work into tasks by phase; turn one into a ticket when it's ready to be worked." />
					{:else}
						{#each groups as [phase, tasks] (phase)}
							<div class="border-border border-b last:border-b-0">
								<div class="bg-sunken/60 flex items-center justify-between gap-2 px-4 py-1.5">
									<h3 class="text-muted text-xs font-semibold tracking-wide uppercase">{phase || 'No phase'}</h3>
									<span class="text-muted text-xs tabular">
										{tasks.filter((t) => t.status === 'done').length} / {tasks.length}
										{#if tech}<IconButton icon={Plus} size="sm" label="Add task to {phase || 'no phase'}" onclick={() => (task = { phase })} />{/if}
									</span>
								</div>
								<ul class="divide-border divide-y">
									{#each tasks as t (t.id)}
										{@const ts = taskStatus(t.status)}
										<li class="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-2.5 text-sm">
											<div class="min-w-0 flex-1 basis-60">
												<div class="font-medium {t.status === 'done' ? 'text-muted line-through' : ''}">{t.title}</div>
												<div class="text-muted flex flex-wrap gap-x-2 text-xs">
													<span>{t.assignee_name ?? 'Unassigned'}</span>
													{#if t.estimate_minutes}<span>est. {fmtMinutes(t.estimate_minutes)}</span>{/if}
													{#if t.logged_minutes}<span>{fmtMinutes(t.logged_minutes)} logged</span>{/if}
													{#if t.due_date}<span class={t.due_date < today && t.status !== 'done' ? 'text-danger' : ''}>due {dateText(t.due_date)}</span>{/if}
												</div>
											</div>
											{#if t.ticket_id}
												<a class="link text-xs whitespace-nowrap" href="/tickets/{t.ticket_id}">T-{t.ticket_number}{t.ticket_status ? ` · ${t.ticket_status}` : ''}</a>
											{:else if tech}
												<Button size="xs" variant="ghost" icon={Ticket} loading={making === t.id} onclick={() => makeTicket(t)}>Make a ticket</Button>
											{/if}
											{#if tech}
												<Select
													aria-label="Status of {t.title}"
													class="w-24"
													value={t.status}
													onchange={(e) => setStatus(t, e.currentTarget.value as TaskStatus)}
													options={taskStatuses.map((x) => ({ value: x.value, label: x.label }))}
												/>
												<IconButton icon={Pencil} size="sm" label="Edit {t.title}" onclick={() => (task = { task: t })} />
												<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {t.title}" onclick={() => removeTask(t)} />
											{:else}
												<Badge tone={ts.tone}>{ts.label}</Badge>
											{/if}
										</li>
									{/each}
								</ul>
							</div>
						{/each}
					{/if}
				</section>

				<section class="card" aria-labelledby="time-h">
					<header class="panel-head">
						<h2 id="time-h" class="panel-title">Time on this project</h2>
						{#if tech}<Button size="sm" icon={Plus} onclick={() => (logging = true)}>Log time</Button>{/if}
					</header>
					<Async res={entries} compact>
						{#snippet children(list)}
							{#if !list.length}
								<EmptyState compact icon={Clock} title="No time logged" description="Time on the project and on its tickets counts towards the budget." />
							{:else}
								<div class="overflow-x-auto">
									<table class="table">
										<caption class="sr-only">Time entries</caption>
										<thead>
											<tr><th>Date</th><th>Who</th><th>For</th><th class="hidden md:table-cell">Note</th><th class="text-right">Time</th>{#if list.some((e) => e.amount != null)}<th class="text-right">Amount</th>{/if}</tr>
										</thead>
										<tbody>
											{#each list as e (e.id)}
												<tr>
													<td class="whitespace-nowrap">{dateText(localDay(new Date(e.started_at)))}</td>
													<td class="whitespace-nowrap">{e.user_name}</td>
													<td class="min-w-32">
														{#if e.ticket_id}<a class="link" href="/tickets/{e.ticket_id}">{entryTarget(e)}</a>{:else}{e.work_type_name}{/if}
														{#if e.ticket_id}<span class="text-muted block text-xs">{e.work_type_name}</span>{/if}
													</td>
													<td class="hidden max-w-72 text-xs whitespace-pre-line md:table-cell">{e.note}</td>
													<td class="text-right whitespace-nowrap tabular">{e.ended_at === null ? 'running' : fmtMinutes(e.minutes)}</td>
													{#if list.some((x) => x.amount != null)}<td class="text-right tabular">{money(e.amount)}</td>{/if}
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
							{/if}
						{/snippet}
					</Async>
				</section>
			</div>

			<aside class="space-y-5">
				<section class="card p-4" aria-labelledby="budget-h">
					<h2 id="budget-h" class="panel-title mb-2">Budget</h2>
					<BudgetBar logged={p.logged_minutes} budget={p.budget_minutes} />
					<dl class="dl mt-3">
						<dt>Budget</dt><dd class="tabular">{p.budget_minutes ? fmtMinutes(p.budget_minutes) : 'None'}</dd>
						<dt>Logged</dt><dd class="tabular">{fmtMinutes(p.logged_minutes)}</dd>
						{#if p.budget_minutes}<dt>Left</dt><dd class="tabular {p.logged_minutes > p.budget_minutes ? 'text-danger' : ''}">{fmtMinutes(p.budget_minutes - p.logged_minutes)}</dd>{/if}
						<dt>Estimated</dt><dd class="tabular">{fmtMinutes(p.estimate_minutes)}{#if p.budget_minutes && p.estimate_minutes > p.budget_minutes}<span class="text-warning"> (over budget)</span>{/if}</dd>
					</dl>
				</section>
				<section class="card p-4" aria-labelledby="burn-h">
					<h2 id="burn-h" class="panel-title mb-3">By week</h2>
					<BurnChart burn={p.burn} budget={p.budget_minutes} />
				</section>
			</aside>
		</div>

		{#if editing}
			<ProjectModal project={p} onclose={() => (editing = false)} onsaved={() => project.reload()} />
		{/if}
		{#if task}
			<TaskModal
				projectId={p.id}
				task={task.task}
				phase={task.phase}
				phases={[...new Set(p.task_list.map((t) => t.phase).filter(Boolean))]}
				technicians={techs}
				onclose={() => (task = null)}
				onsaved={() => project.reload()}
			/>
		{/if}
		{#if logging}
			<LogTimeModal projectId={p.id} onclose={() => (logging = false)} onsaved={reload} />
		{/if}
	{/snippet}
</Async>
