<script lang="ts">
	import { CalendarCheck, ChevronLeft, ChevronRight, Clock, ListChecks, Pencil, Plus, Send, Trash2 } from '@lucide/svelte';
	import { api, qs } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { allowed, can, session } from '#lib/session.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Technician } from '#lib/types.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import { entryTarget, weekStatus } from '#lib/work/meta.js';
	import { loadCurrency, money } from '#lib/work/money.svelte.js';
	import { addDays, dayLabel, daysBetween, fmtMinutes, localDay, mondayOf, timeOf, weekLabel } from '#lib/work/time.js';
	import type { TimeEntry, Week } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import LogTimeModal from '#lib/components/work/LogTimeModal.svelte';
	import TimerCard from '#lib/components/work/TimerCard.svelte';

	const approver = $derived(allowed('time.approve'));
	const today = localDay();
	const week = $derived(/^\d{4}-\d{2}-\d{2}$/.test(param('week')) ? mondayOf(param('week')) : mondayOf(today));
	const userId = $derived(approver ? param('user_id') : '');
	const own = $derived(!userId || userId === session.user?.id);

	const data = resource(() => api.get<Week>(`/timesheets${qs({ week, user_id: userId || undefined })}`));
	let techs = $state<Technician[]>([]);
	$effect(() => {
		loadCurrency();
		if (approver) ticketMeta().then((m) => (techs = m.technicians)).catch(() => {});
	});

	let logging = $state<{ day?: string } | null>(null);
	let editing = $state<TimeEntry | null>(null);
	let submitting = $state(false);

	const days = $derived(Array.from({ length: 7 }, (_, i) => addDays(week, i)));
	function byDay(entries: TimeEntry[]): TimeEntry[][] {
		const out: TimeEntry[][] = days.map(() => []);
		for (const e of entries) {
			const i = Math.min(6, Math.max(0, daysBetween(week, localDay(new Date(e.started_at)))));
			out[i].push(e);
		}
		return out;
	}
	const sum = (list: TimeEntry[]) => list.reduce((n, e) => n + (e.minutes ?? 0), 0);
	const open = (s: string) => s === 'open' || s === 'rejected';
	const editable = (e: TimeEntry, status: string) => open(status) && !e.invoiced && e.ended_at !== null;

	async function remove(e: TimeEntry) {
		const ok = await confirmAction({ title: 'Delete this time entry?', message: `${fmtMinutes(e.minutes)} on ${entryTarget(e)}.`, confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/time/${e.id}`), 'Time entry deleted.'))) data.reload();
	}
	async function submit(w: Week) {
		const running = w.entries.some((e) => e.ended_at === null);
		if (running) {
			toast.error('Stop the timer before submitting the week.');
			return;
		}
		const ok = await confirmAction({
			title: `Submit the week of ${weekLabel(week)}?`,
			message: `${fmtMinutes(w.timesheet.minutes)} logged. You can't change it once it's submitted unless it's sent back.`,
			confirmLabel: 'Submit'
		});
		if (!ok) return;
		submitting = true;
		if (await attempt(() => api.post('/timesheets/submit', { week }), 'Week submitted for approval.')) data.reload();
		submitting = false;
	}
	const personOptions = $derived([
		{ value: '', label: 'Me' },
		...techs.filter((t) => t.id !== session.user?.id).map((t) => ({ value: t.id, label: t.name }))
	]);
</script>

<PageHeader
	title={own ? 'My time' : `${data.data?.timesheet.user_name ?? 'Time'}`}
	description={own ? 'Your logged time by week. Submit the week when it’s complete; an approver checks it before it’s billed.' : 'Their logged time for the week.'}
>
	{#snippet actions()}
		{#if approver}<Button href="/time/approvals" icon={ListChecks}>Approvals</Button>{/if}
		{#if can('technician')}<Button variant="primary" icon={Plus} onclick={() => (logging = {})}>Log time</Button>{/if}
	{/snippet}
</PageHeader>

<div class="mb-4 flex flex-wrap items-center gap-2">
	<div class="flex items-center gap-1">
		<IconButton icon={ChevronLeft} label="Previous week" onclick={() => setParams({ week: addDays(week, -7) })} />
		<IconButton icon={ChevronRight} label="Next week" onclick={() => setParams({ week: addDays(week, 7) })} />
	</div>
	<h2 class="text-base font-semibold" aria-live="polite">{weekLabel(week)}</h2>
	{#if week !== mondayOf(today)}<Button size="sm" variant="ghost" onclick={() => setParams({ week: null })}>This week</Button>{/if}
	{#if approver}
		<Select aria-label="Whose time" class="ml-auto w-full sm:w-56" value={userId} onchange={(e) => setParams({ user_id: e.currentTarget.value || null })} options={personOptions} />
	{/if}
</div>

<div class="grid gap-5 lg:grid-cols-[minmax(0,1fr)_20rem]">
	<div class="min-w-0 space-y-4">
		<Async res={data}>
			{#snippet children(w)}
				{@const st = weekStatus[w.timesheet.status]}
				{@const groups = byDay(w.entries)}
				<section class="card p-4" aria-labelledby="sheet-h">
					<div class="flex flex-wrap items-center gap-3">
						<h2 id="sheet-h" class="sr-only">Timesheet</h2>
						<Badge tone={st.tone} dot>{st.label}</Badge>
						<span class="text-sm"><span class="font-semibold tabular">{fmtMinutes(w.timesheet.minutes)}</span> <span class="text-muted">logged</span></span>
						<span class="text-sm"><span class="font-semibold tabular">{fmtMinutes(w.timesheet.billable_minutes)}</span> <span class="text-muted">billable</span></span>
						{#if own && open(w.timesheet.status)}
							<Button class="ml-auto" variant="primary" size="sm" icon={Send} loading={submitting} disabled={!w.entries.length} onclick={() => submit(w)}>
								{w.timesheet.status === 'rejected' ? 'Resubmit week' : 'Submit week'}
							</Button>
						{/if}
					</div>
					{#if w.timesheet.decided_by_name && (w.timesheet.status === 'approved' || w.timesheet.status === 'rejected')}
						<p class="text-muted mt-2 text-sm">
							{st.label} by {w.timesheet.decided_by_name}{#if w.timesheet.decided_at}, {new Date(w.timesheet.decided_at).toLocaleString()}{/if}.
						</p>
						{#if w.timesheet.note}
							<blockquote class="border-border mt-1.5 border-l-2 pl-3 text-sm whitespace-pre-line">{w.timesheet.note}</blockquote>
						{/if}
					{:else if w.timesheet.status === 'submitted' && w.timesheet.submitted_at}
						<p class="text-muted mt-2 text-sm">Submitted {new Date(w.timesheet.submitted_at).toLocaleString()}; waiting for approval.</p>
					{/if}
				</section>

				{#if !w.entries.length}
					<div class="card">
						<EmptyState icon={Clock} title="No time this week" description={own ? 'Start the timer while you work, or log time afterwards.' : 'Nothing logged.'}>
							{#snippet action()}{#if can('technician') && open(w.timesheet.status)}<Button variant="primary" icon={Plus} onclick={() => (logging = {})}>Log time</Button>{/if}{/snippet}
						</EmptyState>
					</div>
				{:else}
					<div class="space-y-3">
						{#each days as d, i (d)}
							{@const list = groups[i]}
							<section class="card" aria-labelledby="day-{d}">
								<header class="panel-head min-h-10 py-2">
									<h3 id="day-{d}" class="text-sm font-semibold {d === today ? 'text-accent' : ''}">
										{dayLabel(d, { weekday: 'long', day: 'numeric', month: 'short' })}{#if d === today}<span class="sr-only"> (today)</span>{/if}
									</h3>
									<div class="flex items-center gap-2">
										<span class="text-muted text-sm tabular">{list.length ? fmtMinutes(sum(list)) : '–'}</span>
										{#if can('technician') && open(w.timesheet.status)}
											<IconButton icon={Plus} size="sm" label="Log time on {dayLabel(d)}" onclick={() => (logging = { day: d })} />
										{/if}
									</div>
								</header>
								{#if list.length}
									<ul class="divide-border divide-y">
										{#each list as e (e.id)}
											<li class="flex flex-wrap items-start gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
												<span class="text-muted w-24 shrink-0 text-xs tabular">
													{timeOf(e.started_at)}{#if e.ended_at}–{timeOf(e.ended_at)}{/if}
												</span>
												<div class="min-w-0 flex-1 basis-56">
													<div class="flex flex-wrap items-center gap-1.5">
														{#if e.ticket_id}
															<a class="link font-medium" href="/tickets/{e.ticket_id}">{entryTarget(e)}</a>
														{:else if e.project_id}
															<a class="link font-medium" href="/projects/{e.project_id}">{entryTarget(e)}</a>
														{:else}
															<span class="font-medium">{entryTarget(e)}</span>
														{/if}
														{#if e.ticket_id && e.client_name}<span class="text-muted text-xs">· {e.client_name}</span>{/if}
													</div>
													<div class="text-muted mt-0.5 flex flex-wrap items-center gap-1.5 text-xs">
														{e.work_type_name}
														{#if e.billable}<Badge tone="accent">Billable</Badge>{:else}<Badge>Not billable</Badge>{/if}
														{#if e.coverage}<Badge tone="info">{e.coverage}{e.contract_name ? ` · ${e.contract_name}` : ''}</Badge>{/if}
														{#if e.invoiced}<Badge tone="success">Invoiced</Badge>{/if}
														{#if e.ended_at === null}<Badge tone="warning" dot>Running</Badge>{/if}
													</div>
													{#if e.note}<p class="mt-1 whitespace-pre-line">{e.note}</p>{/if}
												</div>
												<div class="ml-auto flex items-center gap-1">
													<span class="text-right">
														<span class="block font-medium tabular">{e.ended_at === null ? 'running' : fmtMinutes(e.minutes)}</span>
														{#if e.amount != null}<span class="text-muted block text-xs tabular">{money(e.amount)}</span>{/if}
													</span>
													{#if editable(e, w.timesheet.status)}
														<IconButton icon={Pencil} size="sm" label="Edit entry" onclick={() => (editing = e)} />
														<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete entry" onclick={() => remove(e)} />
													{/if}
												</div>
											</li>
										{/each}
									</ul>
								{/if}
							</section>
						{/each}
					</div>
				{/if}
			{/snippet}
		</Async>
	</div>

	<aside class="space-y-4">
		{#if own && can('technician')}
			<TimerCard onchange={() => data.reload()} />
		{/if}
		{#if approver}
			<a href="/time/approvals" class="card hover:border-border-strong flex items-center gap-3 p-4 text-sm">
				<CalendarCheck class="text-muted size-5" aria-hidden="true" />
				<span><span class="font-medium">Timesheet approvals</span><span class="text-muted block text-xs">Weeks waiting for a decision</span></span>
			</a>
		{/if}
	</aside>
</div>

{#if logging}
	<LogTimeModal day={logging.day} userId={own ? undefined : userId} onclose={() => (logging = null)} onsaved={() => data.reload()} />
{/if}
{#if editing}
	<LogTimeModal entry={editing} onclose={() => (editing = null)} onsaved={() => data.reload()} />
{/if}
