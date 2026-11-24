<script lang="ts">
	import { CalendarClock, Plus } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { ago, datetime } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import type { ReportSchedule } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import ScheduleDrawer, { rangeLabels, reportLabels, timetableLabel } from './ScheduleDrawer.svelte';

	/** Report schedules: the user's own, or everyone's for an admin. */
	let { clientId = '' }: { clientId?: string } = $props();
	const list = resource(() => api.get<ReportSchedule[]>('/report-schedules'));
	let open = $state<ReportSchedule | 'new' | null>(null);
	const recipients = (s: ReportSchedule) => s.user_ids.length + s.contact_ids.length + s.extra_emails.length;
</script>

<section class="card" aria-labelledby="sched-h">
	<header class="panel-head">
		<div>
			<h2 id="sched-h" class="panel-title">Scheduled reports</h2>
			<p class="text-muted text-xs">PDFs emailed on a timetable. Each runs with its owner’s access at the time it’s sent.</p>
		</div>
		<Button size="sm" variant="primary" icon={Plus} onclick={() => (open = 'new')}>New schedule</Button>
	</header>
	<Async res={list}>
		{#snippet children(rows)}
			{#if !rows.length}
				<EmptyState compact icon={CalendarClock} title="No scheduled reports" description="Schedule any report to have it emailed as a PDF every week, month or quarter." />
			{:else}
				<div class="overflow-x-auto">
					<table class="table">
						<caption class="sr-only">Scheduled reports</caption>
						<thead>
							<tr><th>Name</th><th>Report</th><th class="hidden md:table-cell">When</th><th class="text-right">Recipients</th><th>Next</th><th>Last</th></tr>
						</thead>
						<tbody>
							{#each rows as s (s.id)}
								<tr>
									<td>
										<button type="button" class="hover:text-accent text-left font-medium" onclick={() => (open = s)}>{s.name}</button>
										<div class="text-muted text-xs">{s.owner_name}</div>
									</td>
									<td>{reportLabels[s.report]}{#if s.client_name}<div class="text-muted text-xs">{s.client_name}</div>{/if}</td>
									<td class="hidden md:table-cell">{timetableLabel(s.cron)}<div class="text-muted text-xs">{s.params.range ? rangeLabels[s.params.range] : ''} · {s.timezone}</div></td>
									<td class="text-right tabular">{recipients(s)}</td>
									<td class="whitespace-nowrap">{#if s.enabled && s.next_run_at}<span title={datetime(s.next_run_at)}>{datetime(s.next_run_at)}</span>{:else}<Badge>Off</Badge>{/if}</td>
									<td class="whitespace-nowrap">
										{#if s.last_status}
											<Badge tone={s.last_status === 'sent' ? 'success' : 'danger'} title={s.last_error ?? undefined}>{s.last_status}</Badge>
											<span class="text-muted text-xs">{ago(s.last_run_at)}</span>
										{:else}<span class="text-muted">–</span>{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		{/snippet}
	</Async>
</section>

{#if open}
	<ScheduleDrawer
		schedule={open === 'new' ? null : open}
		{clientId}
		onclose={() => (open = null)}
		onsaved={() => {
			open = null;
			list.reload();
		}}
	/>
{/if}
