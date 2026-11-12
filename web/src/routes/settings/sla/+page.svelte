<script lang="ts">
	import { CalendarClock, Pencil, Plus, Star, Timer, Trash2, X } from '@lucide/svelte';
	import { api } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { plural } from '#lib/format.js';
	import { resource } from '#lib/resource.svelte.js';
	import { minutes } from '#lib/servicedesk/sla.js';
	import { priorities } from '#lib/servicedesk/tickets.svelte.js';
	import { attempt } from '#lib/toast.svelte.js';
	import type { BusinessCalendar, Priority, SlaPolicy, WeekHours } from '#lib/types.js';
	import Async from '#lib/ui/Async.svelte';
	import Badge from '#lib/ui/Badge.svelte';
	import Button from '#lib/ui/Button.svelte';
	import Checkbox from '#lib/ui/Checkbox.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import Field from '#lib/ui/Field.svelte';
	import IconButton from '#lib/ui/IconButton.svelte';
	import Input from '#lib/ui/Input.svelte';
	import Modal from '#lib/ui/Modal.svelte';
	import Select from '#lib/ui/Select.svelte';
	import Switch from '#lib/ui/Switch.svelte';

	const calendars = resource(() => api.get<BusinessCalendar[]>('/sla/calendars'));
	const policies = resource(() => api.get<SlaPolicy[]>('/sla/policies'));
	const channels = resource(() => api.get<{ id: string; name: string }[]>('/notification-channels'));
	const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
	const zones: string[] = (() => {
		try {
			return (Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf('timeZone');
		} catch {
			return ['UTC'];
		}
	})();
	let saving = $state(false);

	const hhmm = (m: number) => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
	const toMin = (s: string) => {
		const [h, m] = s.split(':').map(Number);
		return Math.min(1440, (h || 0) * 60 + (m || 0));
	};
	function summary(h: WeekHours): string {
		const open = h.map((d, i) => (d.length ? `${days[i].slice(0, 3)} ${d.map(([a, b]) => `${hhmm(a)}–${hhmm(b)}`).join(', ')}` : '')).filter(Boolean);
		return open.join(' · ') || 'Closed';
	}

	// --- calendars ------------------------------------------------------------------------------
	type CalDraft = { id: string | null; name: string; timezone: string; days: { open: boolean; from: string; to: string }[]; holidays: { day: string; name: string }[] };
	let cal = $state<CalDraft | null>(null);
	function editCal(c?: BusinessCalendar) {
		cal = c
			? {
					id: c.id, name: c.name, timezone: c.timezone, holidays: c.holidays.map((h) => ({ ...h })),
					days: c.hours.map((d) => ({ open: d.length > 0, from: hhmm(d[0]?.[0] ?? 540), to: hhmm(d[d.length - 1]?.[1] ?? 1020) }))
				}
			: {
					id: null, name: '', timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC', holidays: [],
					days: days.map((_, i) => ({ open: i < 5, from: '09:00', to: '17:00' }))
				};
	}
	async function saveCal(e: SubmitEvent) {
		e.preventDefault();
		const c = cal!;
		const body = {
			name: c.name, timezone: c.timezone,
			hours: c.days.map((d) => (d.open ? [[toMin(d.from), toMin(d.to)]] : [])),
			holidays: c.holidays.filter((h) => h.day)
		};
		saving = true;
		const ok = await attempt(() => (c.id ? api.put(`/sla/calendars/${c.id}`, body) : api.post('/sla/calendars', body)), `${c.name} saved.`);
		saving = false;
		if (ok) {
			cal = null;
			calendars.reload();
			policies.reload();
		}
	}
	async function removeCal(c: BusinessCalendar) {
		const ok = await confirmAction({ title: `Delete ${c.name}?`, message: c.policies ? `${plural(c.policies, 'policy', 'policies')} use it; their clocks will run around the clock.` : undefined, confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/sla/calendars/${c.id}`), `${c.name} deleted.`))) {
			calendars.reload();
			policies.reload();
		}
	}

	// --- policies -------------------------------------------------------------------------------
	type Unit = 'min' | 'h' | 'd';
	type Amount = { n: string; unit: Unit };
	type PolDraft = {
		id: string | null; name: string; calendar_id: string; is_default: boolean; notify_assignee: boolean; channel_ids: string[];
		targets: { priority: Priority; respond: Amount; update: Amount; resolve: Amount }[];
	};
	let pol = $state<PolDraft | null>(null);
	const split = (m: number | null): Amount => (!m ? { n: '', unit: 'h' } : m % 1440 === 0 ? { n: String(m / 1440), unit: 'd' } : m % 60 === 0 ? { n: String(m / 60), unit: 'h' } : { n: String(m), unit: 'min' });
	const join = (a: Amount): number | null => (a.n.trim() ? Math.round(Number(a.n) * (a.unit === 'd' ? 1440 : a.unit === 'h' ? 60 : 1)) : null);
	const defaults: Record<Priority, [number, number, number]> = { 1: [15, 60, 240], 2: [60, 240, 480], 3: [240, 480, 1440 * 2], 4: [480, 1440, 1440 * 5] };
	function editPol(p?: SlaPolicy) {
		pol = {
			id: p?.id ?? null, name: p?.name ?? '', calendar_id: p?.calendar_id ?? calendars.data?.[0]?.id ?? '', is_default: p?.is_default ?? !policies.data?.length,
			notify_assignee: p?.notify_assignee ?? true, channel_ids: [...(p?.channel_ids ?? [])],
			targets: priorities.map(({ value }) => {
				const t = p?.targets.find((x) => x.priority === value);
				const d = defaults[value];
				return { priority: value, respond: split(p ? (t?.respond_mins ?? null) : d[0]), update: split(p ? (t?.update_mins ?? null) : d[1]), resolve: split(p ? (t?.resolve_mins ?? null) : d[2]) };
			})
		};
	}
	async function savePol(e: SubmitEvent) {
		e.preventDefault();
		const p = pol!;
		const body = {
			name: p.name, calendar_id: p.calendar_id || null, is_default: p.is_default, notify_assignee: p.notify_assignee, channel_ids: p.channel_ids,
			targets: p.targets.map((t) => ({ priority: t.priority, respond_mins: join(t.respond), update_mins: join(t.update), resolve_mins: join(t.resolve) }))
		};
		saving = true;
		const ok = await attempt(() => (p.id ? api.put(`/sla/policies/${p.id}`, body) : api.post('/sla/policies', body)), `${p.name} saved. Open tickets are being recalculated.`);
		saving = false;
		if (ok) {
			pol = null;
			policies.reload();
		}
	}
	async function removePol(p: SlaPolicy) {
		const ok = await confirmAction({ title: `Delete ${p.name}?`, message: 'Its clients fall back to the default policy.', confirmLabel: 'Delete', danger: true });
		if (ok && (await attempt(() => api.del(`/sla/policies/${p.id}`), `${p.name} deleted.`))) policies.reload();
	}
	const units = [{ value: 'min', label: 'min' }, { value: 'h', label: 'hours' }, { value: 'd', label: 'days' }];
</script>

<div class="max-w-4xl space-y-5">
	<section class="card" aria-labelledby="pol-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="pol-h" class="font-semibold">SLA policies</h2>
				<p class="text-muted text-xs">
					Response, update and resolution targets per priority, in business time. The clock pauses while a ticket waits on the client. Warnings go out at 75% and again on a breach.
				</p>
			</div>
			<Button variant="primary" icon={Plus} onclick={() => editPol()}>Add policy</Button>
		</header>
		<Async res={policies} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as p (p.id)}
							<li class="flex flex-wrap items-start gap-3 px-5 py-3 text-sm">
								<div class="min-w-0 flex-1">
									<div class="flex flex-wrap items-center gap-1.5 font-medium">
										{p.name}
										{#if p.is_default}<Badge tone="accent" icon={Star}>Default</Badge>{/if}
										<span class="text-muted text-xs font-normal">· {p.calendar_name ?? 'around the clock'} · {plural(p.clients, 'client')} · {plural(p.open_tickets, 'open ticket')}</span>
									</div>
									<table class="text-muted mt-1.5 text-xs">
										<thead class="sr-only"><tr><th>Priority</th><th>First response</th><th>Update</th><th>Resolution</th></tr></thead>
										<tbody>
											{#each p.targets as t (t.priority)}
												<tr>
													<td class="pr-3 font-medium">P{t.priority}</td>
													<td class="pr-3">respond {minutes(t.respond_mins)}</td>
													<td class="pr-3">update {minutes(t.update_mins)}</td>
													<td>resolve {minutes(t.resolve_mins)}</td>
												</tr>
											{/each}
										</tbody>
									</table>
								</div>
								<IconButton icon={Pencil} size="sm" label="Edit {p.name}" onclick={() => editPol(p)} />
								<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {p.name}" onclick={() => removePol(p)} />
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={Timer} title="No SLA policies" description="Add one and mark it the default to put every ticket on the clock; give clients with other contracts their own." />
				{/if}
			{/snippet}
		</Async>
	</section>

	<section class="card" aria-labelledby="cal-h">
		<header class="border-border flex items-center justify-between gap-3 border-b px-5 py-3">
			<div>
				<h2 id="cal-h" class="font-semibold">Business hours</h2>
				<p class="text-muted text-xs">When the SLA clock runs, in a time zone, minus holidays. A policy without hours runs around the clock.</p>
			</div>
			<Button icon={Plus} onclick={() => editCal()}>Add hours</Button>
		</header>
		<Async res={calendars} compact>
			{#snippet children(list)}
				{#if list.length}
					<ul class="divide-border divide-y">
						{#each list as c (c.id)}
							<li class="flex items-center gap-3 px-5 py-3 text-sm">
								<div class="min-w-0 flex-1">
									<div class="font-medium">{c.name} <span class="text-muted text-xs font-normal">· {c.timezone} · {plural(c.holidays.length, 'holiday')}</span></div>
									<div class="text-muted truncate text-xs">{summary(c.hours)}</div>
								</div>
								<IconButton icon={Pencil} size="sm" label="Edit {c.name}" onclick={() => editCal(c)} />
								<IconButton icon={Trash2} size="sm" variant="danger-ghost" label="Delete {c.name}" onclick={() => removeCal(c)} />
							</li>
						{/each}
					</ul>
				{:else}
					<EmptyState compact icon={CalendarClock} title="No business hours" description="For example Monday to Friday, 08:00–18:00 in your office's time zone." />
				{/if}
			{/snippet}
		</Async>
	</section>
</div>

{#if cal}
	<Modal title={cal.id ? `Edit ${cal.name}` : 'Add business hours'} onclose={() => (cal = null)} size="lg">
		<form id="cal-form" class="space-y-4" onsubmit={saveCal}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="cal-name" required><Input id="cal-name" bind:value={cal.name} required maxlength={100} placeholder="Office hours" /></Field>
				<Field label="Time zone" id="cal-tz"><Select id="cal-tz" class="w-full" bind:value={cal.timezone} options={zones.map((z) => ({ value: z, label: z }))} /></Field>
			</div>
			<fieldset>
				<legend class="label">Opening hours</legend>
				<div class="space-y-1.5">
					{#each cal.days as d, i (i)}
						<div class="flex flex-wrap items-center gap-2 text-sm">
							<div class="w-32"><Checkbox bind:checked={d.open}>{days[i]}</Checkbox></div>
							{#if d.open}
								<Input type="time" aria-label="{days[i]} opens" class="w-28" bind:value={d.from} />
								<span class="text-muted">to</span>
								<Input type="time" aria-label="{days[i]} closes" class="w-28" bind:value={d.to} />
							{:else}
								<span class="text-muted">Closed</span>
							{/if}
						</div>
					{/each}
				</div>
			</fieldset>
			<fieldset>
				<legend class="label">Holidays</legend>
				<div class="space-y-1.5">
					{#each cal.holidays as h, i (i)}
						<div class="flex items-center gap-2">
							<Input type="date" aria-label="Date" class="w-40" bind:value={h.day} />
							<Input aria-label="Name" class="min-w-0 flex-1" bind:value={h.name} maxlength={100} placeholder="New Year's Day" />
							<IconButton icon={X} size="sm" label="Remove holiday" onclick={() => cal!.holidays.splice(i, 1)} />
						</div>
					{/each}
				</div>
				<Button size="sm" variant="ghost" icon={Plus} class="mt-1" onclick={() => cal!.holidays.push({ day: '', name: '' })}>Add holiday</Button>
			</fieldset>
		</form>
		{#snippet footer()}
			<Button onclick={() => (cal = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="cal-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}

{#if pol}
	<Modal title={pol.id ? `Edit ${pol.name}` : 'Add SLA policy'} onclose={() => (pol = null)} size="lg">
		<form id="pol-form" class="space-y-4" onsubmit={savePol}>
			<div class="grid gap-3 sm:grid-cols-2">
				<Field label="Name" id="pol-name" required><Input id="pol-name" bind:value={pol.name} required maxlength={100} placeholder="Standard" /></Field>
				<Field label="Business hours" id="pol-cal">
					<Select id="pol-cal" class="w-full" bind:value={pol.calendar_id} options={[{ value: '', label: 'Around the clock' }, ...(calendars.data ?? []).map((c) => ({ value: c.id, label: c.name }))]} />
				</Field>
			</div>
			<div class="overflow-x-auto">
				<table class="table">
					<thead><tr><th>Priority</th><th>First response</th><th>Next update</th><th>Resolution</th></tr></thead>
					<tbody>
						{#each pol.targets as t (t.priority)}
							<tr>
								<th scope="row" class="font-medium whitespace-nowrap">{priorities[t.priority - 1].label}</th>
								{#each ['respond', 'update', 'resolve'] as const as k (k)}
									<td>
										<div class="flex gap-1">
											<Input type="number" min="0" step="any" aria-label="P{t.priority} {k} target" class="w-16" bind:value={t[k].n} placeholder="–" />
											<Select aria-label="P{t.priority} {k} unit" class="w-24" bind:value={t[k].unit} options={units} />
										</div>
									</td>
								{/each}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			<p class="hint">Leave a target empty to not track it. Updates are measured between public replies once the first one is in.</p>
			<fieldset>
				<legend class="label">Warnings and breaches go to</legend>
				<div class="space-y-1.5">
					<Switch bind:checked={pol.notify_assignee}>The ticket's assignee, by email</Switch>
					{#each channels.data ?? [] as c (c.id)}
						<Checkbox checked={pol.channel_ids.includes(c.id)} onchange={(on: boolean) => (pol!.channel_ids = on ? [...pol!.channel_ids, c.id] : pol!.channel_ids.filter((x) => x !== c.id))}>{c.name}</Checkbox>
					{/each}
				</div>
			</fieldset>
			<Switch bind:checked={pol.is_default}>Default policy, for clients without one of their own</Switch>
		</form>
		{#snippet footer()}
			<Button onclick={() => (pol = null)}>Cancel</Button>
			<Button variant="primary" type="submit" form="pol-form" loading={saving}>Save</Button>
		{/snippet}
	</Modal>
{/if}
