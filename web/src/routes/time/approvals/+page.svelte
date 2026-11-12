<script lang="ts">
	import { Check, ChevronDown, ChevronRight, ListChecks, Undo2 } from '@lucide/svelte';
	import { api, qs } from '#lib/api.js';
	import { allowed } from '#lib/session.svelte.js';
	import { resource } from '#lib/resource.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import { entryTarget } from '#lib/work/meta.js';
	import { loadCurrency, money } from '#lib/work/money.svelte.js';
	import { dayLabel, fmtMinutes, localDay, timeOf, weekLabel } from '#lib/work/time.js';
	import type { Timesheet, Week } from '#lib/work/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import PageHeader from '#lib/ui/PageHeader.svelte';
	import Textarea from '#lib/ui/Textarea.svelte';

	const permitted = $derived(allowed('time.approve'));
	const pending = resource(() => (permitted ? api.get<Timesheet[]>('/timesheets/pending') : Promise.resolve([] as Timesheet[])));
	$effect(() => {
		loadCurrency();
	});

	let expanded = $state<Record<string, boolean>>({});
	let weeks = $state<Record<string, Week | 'loading' | Error>>({});
	const key = (s: Timesheet) => s.id ?? `${s.user_id}:${s.week_start}`;

	async function toggle(s: Timesheet) {
		const k = key(s);
		expanded[k] = !expanded[k];
		if (expanded[k] && !(weeks[k] && weeks[k] !== 'loading' && !(weeks[k] instanceof Error))) {
			weeks[k] = 'loading';
			try {
				weeks[k] = await api.get<Week>(`/timesheets${qs({ week: s.week_start, user_id: s.user_id })}`);
			} catch (e) {
				weeks[k] = e instanceof Error ? e : new Error(String(e));
			}
		}
	}

	let deciding = $state<{ sheet: Timesheet; approve: boolean; note: string } | null>(null);
	let saving = $state(false);
	async function decide(e: SubmitEvent) {
		e.preventDefault();
		const d = deciding!;
		saving = true;
		const ok = await attempt(
			() => api.post(`/timesheets/${d.sheet.id}/${d.approve ? 'approve' : 'reject'}`, { note: d.note }),
			d.approve ? `${d.sheet.user_name}'s week approved.` : `${d.sheet.user_name}'s week sent back.`
		);
		saving = false;
		if (ok) {
			deciding = null;
			pending.reload();
		}
	}
</script>

<PageHeader
	title="Timesheet approvals"
	count={pending.data?.length ?? null}
	crumbs={[{ label: 'Time', href: '/time' }, { label: 'Approvals' }]}
	description="Submitted weeks. Approving works out each entry's contract coverage and amount, ready for invoicing; sending a week back lets the technician correct it."
/>

{#if !permitted}
	<div class="card"><EmptyState icon={ListChecks} title="Not available" description="Approving timesheets needs the time approval permission." /></div>
{:else}
	<Async res={pending}>
		{#snippet children(list)}
			{#if !list.length}
				<div class="card"><EmptyState icon={ListChecks} title="Nothing to approve" description="Submitted weeks show up here." /></div>
			{:else}
				<ul class="space-y-3">
					{#each list as s (key(s))}
						{@const k = key(s)}
						{@const w = weeks[k]}
						<li class="card">
							<div class="flex flex-wrap items-center gap-3 px-4 py-3">
								<button
									class="hover:text-accent flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left"
									aria-expanded={!!expanded[k]}
									aria-controls="week-{k}"
									onclick={() => toggle(s)}
								>
									{#if expanded[k]}<ChevronDown class="text-muted size-4 shrink-0" aria-hidden="true" />{:else}<ChevronRight class="text-muted size-4 shrink-0" aria-hidden="true" />{/if}
									<span class="min-w-0">
										<span class="block font-medium">{s.user_name}</span>
										<span class="text-muted block text-xs">Week of {weekLabel(s.week_start)}{#if s.submitted_at} · submitted {new Date(s.submitted_at).toLocaleDateString()}{/if}</span>
									</span>
								</button>
								<span class="text-sm tabular"><span class="font-semibold">{fmtMinutes(s.minutes)}</span> <span class="text-muted">· {fmtMinutes(s.billable_minutes)} billable</span></span>
								<div class="flex gap-2">
									<Button size="sm" icon={Undo2} onclick={() => (deciding = { sheet: s, approve: false, note: '' })}>Send back</Button>
									<Button size="sm" variant="primary" icon={Check} onclick={() => (deciding = { sheet: s, approve: true, note: '' })}>Approve</Button>
								</div>
							</div>
							{#if expanded[k]}
								<div id="week-{k}" class="border-border border-t">
									{#if w === 'loading' || !w}
										<p class="text-muted px-4 py-3 text-sm">Loading…</p>
									{:else if w instanceof Error}
										<p class="text-danger px-4 py-3 text-sm" role="alert">{w.message}</p>
									{:else if !w.entries.length}
										<p class="text-muted px-4 py-3 text-sm">No entries.</p>
									{:else}
										<div class="overflow-x-auto">
											<table class="table">
												<caption class="sr-only">{s.user_name}'s entries, week of {weekLabel(s.week_start)}</caption>
												<thead>
													<tr><th>Day</th><th>For</th><th>Work type</th><th>Note</th><th class="text-right">Time</th>{#if w.entries.some((e) => e.amount != null)}<th class="text-right">Amount</th>{/if}</tr>
												</thead>
												<tbody>
													{#each w.entries as e (e.id)}
														<tr>
															<td class="whitespace-nowrap">{dayLabel(localDay(new Date(e.started_at)))} <span class="text-muted text-xs">{timeOf(e.started_at)}</span></td>
															<td class="min-w-40">
																{#if e.ticket_id}<a class="link" href="/tickets/{e.ticket_id}">{entryTarget(e)}</a>{:else}{entryTarget(e)}{/if}
																{#if e.client_name && e.ticket_id}<span class="text-muted block text-xs">{e.client_name}</span>{/if}
															</td>
															<td class="whitespace-nowrap">{e.work_type_name} {#if e.billable}<Badge tone="accent">Billable</Badge>{/if}</td>
															<td class="max-w-80 text-xs whitespace-pre-line">{e.note}</td>
															<td class="text-right whitespace-nowrap tabular">{fmtMinutes(e.minutes)}</td>
															{#if w.entries.some((x) => x.amount != null)}<td class="text-right tabular">{money(e.amount)}</td>{/if}
														</tr>
													{/each}
												</tbody>
											</table>
										</div>
									{/if}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		{/snippet}
	</Async>
{/if}

{#if deciding}
	<Modal
		title={deciding.approve ? `Approve ${deciding.sheet.user_name}'s week?` : `Send ${deciding.sheet.user_name}'s week back?`}
		description="Week of {weekLabel(deciding.sheet.week_start)} · {fmtMinutes(deciding.sheet.minutes)}"
		onclose={() => (deciding = null)}
		size="sm"
	>
		<form id="decide" onsubmit={decide}>
			<Field label={deciding.approve ? 'Note (optional)' : 'What needs fixing'} id="decide-note" required={!deciding.approve}>
				<Textarea id="decide-note" rows={4} bind:value={deciding.note} required={!deciding.approve} maxlength={2000} />
			</Field>
		</form>
		{#snippet footer()}
			<Button onclick={() => (deciding = null)}>Cancel</Button>
			<Button variant={deciding!.approve ? 'primary' : 'danger'} type="submit" form="decide" loading={saving}>{deciding!.approve ? 'Approve' : 'Send back'}</Button>
		{/snippet}
	</Modal>
{/if}
