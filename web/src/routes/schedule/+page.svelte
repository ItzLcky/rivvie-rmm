<script lang="ts">
	import { CalendarDays, ChevronLeft, ChevronRight, Plus } from '@lucide/svelte';
	import { api, qs } from '#lib/api.js';
	import { ticketMeta } from '#lib/servicedesk/tickets.svelte.js';
	import { can } from '#lib/session.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt, toast } from '#lib/toast.svelte.js';
	import type { Technician } from '#lib/types.js';
	import { param, setParams } from '#lib/url.svelte.js';
	import { addDays, dayLabel, fromLocal, localDay, mondayOf, timeOf, weekLabel } from '#lib/work/time.js';
	import type { ScheduleEntry } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Select from '#lib/ui/Select.svelte';
	import ScheduleModal from '#lib/components/work/ScheduleModal.svelte';

	const today = localDay();
	const week = $derived(/^\d{4}-\d{2}-\d{2}$/.test(param('week')) ? mondayOf(param('week')) : mondayOf(today));
	const who = $derived(param('user'));
	const days = $derived(Array.from({ length: 7 }, (_, i) => addDays(week, i)));
	const from = $derived(fromLocal(week));
	const to = $derived(fromLocal(addDays(week, 7)));

	const list = resource(() => api.get<ScheduleEntry[]>(`/schedule${qs({ from: from.toISOString(), to: to.toISOString(), user_id: who || undefined })}`));
	let techs = $state<Technician[]>([]);
	$effect(() => {
		ticketMeta()
			.then((m) => (techs = m.technicians))
			.catch(() => {});
	});
	const rows = $derived.by(() => {
		const all = techs.filter((t) => !who || t.id === who);
		// People with entries who aren't in the technician list (e.g. since disabled) still show.
		for (const e of list.data ?? []) if (!all.some((t) => t.id === e.user_id)) all.push({ id: e.user_id, name: e.user_name, email: '', client_ids: null });
		return all;
	});

	function cell(entries: ScheduleEntry[], user: string, day: string): ScheduleEntry[] {
		const a = fromLocal(day).getTime();
		const b = fromLocal(addDays(day, 1)).getTime();
		return entries.filter((e) => e.user_id === user && new Date(e.starts_at).getTime() < b && new Date(e.ends_at).getTime() > a);
	}
	function span(e: ScheduleEntry, day: string): string {
		const s = new Date(e.starts_at);
		const x = new Date(e.ends_at);
		const startsBefore = localDay(s) < day;
		const endsAfter = localDay(new Date(x.getTime() - 1)) > day;
		return `${startsBefore ? '…' : timeOf(e.starts_at)}–${endsAfter ? '…' : timeOf(e.ends_at)}`;
	}
	const label = (e: ScheduleEntry) => e.title || (e.ticket_number != null ? `T-${e.ticket_number} ${e.ticket_subject ?? ''}` : (e.project_name ?? 'Booked'));

	let editing = $state<ScheduleEntry | null>(null);
	let creating = $state<{ user_id?: string; day?: string } | null>(null);

	// Drag a block to another person or day; the times of day stay the same.
	let dragging = $state<ScheduleEntry | null>(null);
	let over = $state('');
	async function drop(user: string, day: string) {
		const e = dragging;
		dragging = null;
		over = '';
		if (!e) return;
		const s = new Date(e.starts_at);
		const shift = fromLocal(day, '00:00').getTime() - fromLocal(localDay(s), '00:00').getTime();
		if (!shift && user === e.user_id) return;
		const starts = new Date(s.getTime() + shift);
		const ends = new Date(new Date(e.ends_at).getTime() + shift);
		const ok = await attempt(
			() =>
				api.put(`/schedule/${e.id}`, {
					user_id: user,
					starts_at: starts.toISOString(),
					ends_at: ends.toISOString(),
					title: e.title,
					ticket_id: e.ticket_id,
					project_id: e.project_id,
					notes: e.notes
				}),
			'Moved.'
		);
		if (ok) {
			const clash = (list.data ?? []).filter((o) => o.id !== e.id && o.user_id === user && new Date(o.starts_at) < ends && new Date(o.ends_at) > starts).length;
			if (clash) toast.info(`That overlaps ${clash === 1 ? 'another booking' : `${clash} other bookings`}.`);
			list.reload();
		}
	}
	const tech = $derived(can('technician'));
</script>

<PageHeader title="Schedule" description="Who's working on what, and when. Times are in your time zone; drag a booking to move it to another day or person.">
	{#snippet actions()}{#if tech}<Button variant="primary" icon={Plus} onclick={() => (creating = {})}>Schedule work</Button>{/if}{/snippet}
</PageHeader>

<div class="mb-4 flex flex-wrap items-center gap-2">
	<div class="flex items-center gap-1">
		<IconButton icon={ChevronLeft} label="Previous week" onclick={() => setParams({ week: addDays(week, -7) })} />
		<IconButton icon={ChevronRight} label="Next week" onclick={() => setParams({ week: addDays(week, 7) })} />
	</div>
	<h2 class="text-base font-semibold" aria-live="polite">{weekLabel(week)}</h2>
	<Button size="sm" variant="ghost" disabled={week === mondayOf(today)} onclick={() => setParams({ week: null })}>Today</Button>
	<Select
		aria-label="Technician"
		class="w-full sm:ml-auto sm:w-56"
		value={who}
		onchange={(e) => setParams({ user: e.currentTarget.value || null })}
		options={[{ value: '', label: 'Everyone' }, ...techs.map((t) => ({ value: t.id, label: t.name }))]}
	/>
</div>

<Async res={list}>
	{#snippet children(entries)}
		{#if !rows.length}
			<div class="card"><EmptyState icon={CalendarDays} title="No technicians" description="Add technicians under Users to schedule their work." /></div>
		{:else}
			<div class="card overflow-x-auto">
				<table class="w-full min-w-[56rem] table-fixed border-separate border-spacing-0 text-sm">
					<caption class="sr-only">Schedule for the week of {weekLabel(week)}</caption>
					<thead>
						<tr>
							<th scope="col" class="bg-sunken border-border text-muted sticky left-0 z-[1] w-36 border-b px-3 py-2 text-left text-xs font-semibold">Technician</th>
							{#each days as d (d)}
								<th scope="col" class="bg-sunken border-border border-b border-l px-2 py-2 text-left text-xs font-semibold {d === today ? 'text-accent' : 'text-muted'}">
									{dayLabel(d)}{#if d === today}<span class="sr-only"> (today)</span>{/if}
								</th>
							{/each}
						</tr>
					</thead>
					<tbody>
						{#each rows as t (t.id)}
							<tr>
								<th scope="row" class="bg-raised border-border sticky left-0 z-[1] border-b px-3 py-2 text-left align-top font-medium">
									<span class="line-clamp-2">{t.name}</span>
								</th>
								{#each days as d (d)}
									{@const items = cell(entries, t.id, d)}
									{@const k = `${t.id}:${d}`}
									<td
										class="group border-border h-20 border-b border-l p-1 align-top {d === today ? 'bg-accent-soft/30' : ''} {over === k ? 'bg-accent-soft' : ''}"
										ondragover={(ev) => {
											if (dragging) {
												ev.preventDefault();
												over = k;
											}
										}}
										ondragleave={() => over === k && (over = '')}
										ondrop={(ev) => {
											ev.preventDefault();
											drop(t.id, d);
										}}
									>
										<div class="flex flex-col gap-1">
											{#each items as e (e.id)}
												<button
													type="button"
													draggable={tech}
													ondragstart={(ev) => {
														dragging = e;
														ev.dataTransfer?.setData('text/plain', e.id);
													}}
													ondragend={() => {
														dragging = null;
														over = '';
													}}
													onclick={() => tech && (editing = e)}
													class="bg-accent-soft border-accent/30 hover:border-accent block w-full cursor-pointer rounded-md border px-1.5 py-1 text-left text-xs"
													aria-label="{label(e)}, {span(e, d)}{e.client_name ? `, ${e.client_name}` : ''}"
												>
													<span class="text-muted block tabular">{span(e, d)}</span>
													<span class="text-fg line-clamp-2 font-medium">{label(e)}</span>
													{#if e.client_name}<span class="text-muted block truncate">{e.client_name}</span>{/if}
												</button>
											{/each}
											{#if tech}
												<button
													type="button"
													class="text-subtle hover:text-accent hover:bg-hover focus-visible:text-accent flex h-6 w-full cursor-pointer items-center justify-center rounded opacity-0 group-hover:opacity-100 focus-visible:opacity-100 {items.length ? '' : 'h-full min-h-14'}"
													aria-label="Schedule {t.name} on {dayLabel(d, { weekday: 'long', day: 'numeric', month: 'long' })}"
													onclick={() => (creating = { user_id: t.id, day: d })}
												>
													<Plus class="size-4" aria-hidden="true" />
												</button>
											{/if}
										</div>
									</td>
								{/each}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if !entries.length}<p class="text-muted mt-3 text-sm">Nothing booked this week.</p>{/if}
		{/if}
	{/snippet}
</Async>

{#if creating}
	<ScheduleModal technicians={techs} preset={creating} others={list.data ?? []} onclose={() => (creating = null)} onsaved={() => list.reload()} />
{/if}
{#if editing}
	<ScheduleModal entry={editing} technicians={techs} others={list.data ?? []} onclose={() => (editing = null)} onsaved={() => list.reload()} />
{/if}
